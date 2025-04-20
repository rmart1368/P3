#include <iostream>
#include <unordered_map>
#include <map>
#include <string>
#include <vector>
#include "VulnerabilityMapper.h"
#include "DataTable.h"
#include <chrono>
using namespace std;

int main()
{
    VulnerabilityMapper vul_map;
    unordered_map<string, DataTable> cve_id_map;
    multimap<float, string, greater<>> cvss_ordered_map;

    //format key: cve_id  value: <description, published_date, year, os, software, version, severity, cvss>
    //format key: text    value: <string, string, int, string, string, string, string, float>
    //connections from PYTHONSQL --> hashmap database still needs to be implemented
    //will only have inputted values with appropriate search parameters, only need to input values into map and sort

    cve_id_map["4729A"] = {"12/07/2020", "Remote code execution vulnerability", "Microsoft", "Edge", "Windows", "high", 9.1f};
    cve_id_map["1836T"] = {"03/03/2015", "Privilege escalation flaw", "Apple", "Safari", "Mac OS", "medium", 6.4f};
    cve_id_map["9375K"] = {"29/09/2018", "Buffer overflow in image processing", "Adobe", "Photoshop", "Windows", "high", 8.7f};
    cve_id_map["5081J"] = {"22/01/2022", "Authentication bypass via token reuse", "Google", "Chrome", "Linux", "high", 9.5f};
    cve_id_map["6723N"] = {"10/10/2011", "Information disclosure via cache timing", "Intel", "Firmware", "Windows", "low", 3.2f};
    cve_id_map["3517F"] = {"17/04/2019", "Cross-site scripting vulnerability", "Mozilla", "Firefox", "Linux", "medium", 5.8f};
    cve_id_map["9264B"] = {"01/06/2009", "Heap corruption when parsing files", "Oracle", "Java", "Windows", "high", 8.1f};
    cve_id_map["7902L"] = {"05/12/2016", "Insecure deserialization flaw", "Apache", "Struts", "Linux", "high", 9.3f};
    cve_id_map["2391V"] = {"28/03/2013", "SQL injection via crafted query", "PostgreSQL", "psql", "Linux", "medium", 6.0f};
    cve_id_map["6648X"] = {"16/08/2005", "Directory traversal vulnerability", "Cisco", "IOS", "Windows", "low", 2.7f};

    vul_map.multimap_add_and_sort(cve_id_map, cvss_ordered_map);
    vul_map.multimap_print_all_cvss_ordered(cve_id_map, cvss_ordered_map);
    cout << endl;
    //chrono functionality from cppreference
    const auto start{std::chrono::steady_clock::now()};

    vul_map.multimap_print_by_input(cve_id_map, cvss_ordered_map, "severity", "high");

    const auto finish{std::chrono::steady_clock::now()};
    const std::chrono::duration<double> elapsed_seconds{finish - start};
    std::cout << elapsed_seconds.count() << endl;
    return 0;
}
