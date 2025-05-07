#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/tables/system/darwin/smbios_utils.h>
#include <osquery/logger/logger.h>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <string>
#include <fstream>
#include <sstream>

using json = nlohmann::json;

namespace osquery {

// Callback function for curl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class MacOSCompatibilityTable : public TablePlugin {
 private:
    // Cache directory
    const std::string kCacheDir = "/private/var/tmp/sofa";
    const std::string kJsonCache = kCacheDir + "/macos_data_feed.json";
    const std::string kEtagCache = kCacheDir + "/macos_data_feed_etag.txt";

    // SOFA feed URL
    const std::string kSofaUrl = "https://sofafeed.macadmins.io/v1/macos_data_feed.json";
    const std::string kUserAgent = "SOFA-osquery-macOSCompatibilityCheck/1.0";

    TableColumns columns() const {
        return {
            std::make_tuple("system_version", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("system_os_major", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("model_identifier", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("latest_macos", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("latest_compatible_macos", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("is_compatible", INTEGER_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("status", TEXT_TYPE, ColumnOptions::DEFAULT),
        };
    }

    // Create cache directory if it doesn't exist
    bool ensureCacheDir() {
        try {
            if (access(kCacheDir.c_str(), F_OK) != 0) {
                if (mkdir(kCacheDir.c_str(), 0755) != 0) {
                    LOG(ERROR) << "Failed to create cache directory: " << kCacheDir;
                    return false;
                }
            }
            return true;
        } catch (const std::exception& e) {
            LOG(ERROR) << "Exception creating cache directory: " << e.what();
            return false;
        }
    }

    // Read file content
    std::string readFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return "";
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    // Write content to file
    bool writeFile(const std::string& filename, const std::string& content) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        file << content;
        return true;
    }

    // Fetch SOFA json data with etag handling
    std::string fetchSofaJson() {
        if (!ensureCacheDir()) {
            return "";
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            LOG(ERROR) << "Failed to initialize curl";
            return "";
        }

        CURLcode res;
        std::string readBuffer;
        struct curl_slist* headers = NULL;

        // If we have a cached etag, use it
        std::string etag = readFile(kEtagCache);
        if (!etag.empty()) {
            std::string header = "If-None-Match: " + etag;
            headers = curl_slist_append(headers, header.c_str());
        }

        curl_easy_setopt(curl, CURLOPT_URL, kSofaUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_USERAGENT, kUserAgent.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            LOG(ERROR) << "curl_easy_perform() failed: " << curl_easy_strerror(res);
            curl_easy_cleanup(curl);
            return "";
        }

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        // Check for etag in response
        char* new_etag = nullptr;
        res = curl_easy_getinfo(curl, CURLINFO_ETAG, &new_etag);
        if (res == CURLE_OK && new_etag) {
            writeFile(kEtagCache, new_etag);
        }

        curl_easy_cleanup(curl);
        
        // If we got 304 Not Modified, use cached json
        if (http_code == 304) {
            LOG(INFO) << "Using cached SOFA json (304 Not Modified)";
            return readFile(kJsonCache);
        }
        
        // If we got new data, cache it
        if (http_code == 200) {
            writeFile(kJsonCache, readBuffer);
            return readBuffer;
        }
        
        // If we couldn't get new data but have cached data, use it
        if (!readFile(kJsonCache).empty()) {
            LOG(WARNING) << "Failed to fetch new data (HTTP " << http_code << "), using cached data";
            return readFile(kJsonCache);
        }
        
        LOG(ERROR) << "Failed to fetch SOFA data (HTTP " << http_code << ") and no cache available";
        return "";
    }

 public:
    MacOSCompatibilityTable() {
        // Initialize curl
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~MacOSCompatibilityTable() {
        // Clean up curl
        curl_global_cleanup();
    }

    TableRows generate(QueryContext& context) {
        TableRows results;

        // Get system version from os_version table
        auto os_data = SQL::selectAllFrom("os_version");
        if (os_data.empty()) {
            LOG(ERROR) << "Failed to get os_version data";
            return results;
        }
        std::string system_version = os_data.front().at("product_version");
        
        // Extract major OS version (e.g., 14 from 14.5)
        std::string system_os_major = system_version.substr(0, system_version.find("."));
                
        // Get model identifier from system_info table
        auto sys_data = SQL::selectAllFrom("system_info");
        if (sys_data.empty()) {
            LOG(ERROR) << "Failed to get system_info data";
            return results;
        }
        std::string model_identifier = sys_data.front().at("hardware_model");
        
        // Fetch and parse SOFA data
        std::string jsonData = fetchSofaJson();
        
        if (jsonData.empty()) {
            auto r = make_table_row();
            r["system_version"] = system_version;
            r["system_os_major"] = system_os_major;
            r["model_identifier"] = model_identifier;
            r["latest_macos"] = "Unknown";
            r["latest_compatible_macos"] = "Unknown";
            r["is_compatible"] = "-1"; // Error code
            r["status"] = "Could not obtain data";
            results.push_back(std::move(r));
            return results;
        }
        
        try {
            json j = json::parse(jsonData);
            
            std::string latest_os = j["OSVersions"][0]["OSVersion"];
            std::string latest_compatible_os = "Unsupported";
            std::string status = "Pass";
            
            // Check if model is virtual
            if (model_identifier.find("VirtualMac") != std::string::npos) {
                model_identifier = "Macmini9,1"; // Use M1 Mac mini as reference for VMs
            }
            
            // Check if model exists in the feed
            if (j["Models"].contains(model_identifier) && 
                !j["Models"][model_identifier]["SupportedOS"].empty()) {
                latest_compatible_os = j["Models"][model_identifier]["SupportedOS"][0];
            } else {
                status = "Unsupported Hardware";
            }
            
            bool is_compatible = (latest_os == latest_compatible_os);
            if (!is_compatible && status != "Unsupported Hardware") {
                status = "Fail";
            }
            
            auto r = make_table_row();
            r["system_version"] = system_version;
            r["system_os_major"] = system_os_major;
            r["model_identifier"] = model_identifier;
            r["latest_macos"] = latest_os;
            r["latest_compatible_macos"] = latest_compatible_os;
            r["is_compatible"] = is_compatible ? "1" : "0";
            r["status"] = status;
            
            results.push_back(std::move(r));
            
        } catch (const std::exception& e) {
            LOG(ERROR) << "Exception parsing SOFA data: " << e.what();
            
            auto r = make_table_row();
            r["system_version"] = system_version;
            r["system_os_major"] = system_os_major;
            r["model_identifier"] = model_identifier;
            r["latest_macos"] = "Error";
            r["latest_compatible_macos"] = "Error";
            r["is_compatible"] = "-1"; // Error code
            r["status"] = "Error parsing data: " + std::string(e.what());
            
            results.push_back(std::move(r));
        }
        
        return results;
    }
};

REGISTER_OSQUERY_TABLE(MacOSCompatibilityTable);

} // namespace osquery