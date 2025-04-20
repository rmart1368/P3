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
    //format key: cve_id  value: <description, published_date, year, os, software, version, severity, cvss>
    //format key: text    value: <string, string, int, string, string, string, string, float>
    //connections from PYTHONSQL --> hashmap database still needs to be implemented
    //will only have inputted values with appropriate search parameters, only need to input values into map and sort

    //takes in cve_id_map and empty cvss_ordered_map passed by reference to update original values
    //increments through every key in the cve_id_map and adds it to the multimap, which automatically sorts it upon insertion into a tree
    //the data is added and sorted by cvss score (and can have duplicates due to it being a multimap)

    //*node that this SQL_upload function is a placeholder and will be changed once I figure out the input format
    vul_map.unordered_map_SQL_upload();
    vul_map.multimap_add_and_sort();
    vul_map.multimap_print_all_cvss_ordered();
    cout << endl;
    //chrono functionality from cppreference
    const auto start{std::chrono::steady_clock::now()};

    vul_map.multimap_print_by_input("severity", "high");

    const auto finish{std::chrono::steady_clock::now()};
    const std::chrono::duration<double> elapsed_seconds{finish - start};
    std::cout << elapsed_seconds.count() << endl;
    return 0;
}
