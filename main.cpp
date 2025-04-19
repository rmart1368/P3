#include <iostream>
#include <unordered_map>
#include <map>
#include <string>
#include <vector>

using namespace std;

struct DataTable
{
    string published_date;
    string description;
    string vendor;
    string product;
    string os_type;
    string severity;
    float cvss;

    DataTable()
    {
        published_date = "0";
        description = "0";
        vendor = "0";
        product = "0";
        os_type = "0";
        severity = "0";
        cvss = 0.0f;
    }

    DataTable(string date, string desc, string vend, string prod, string os, string sev, float cvss_input)
    {
        published_date = date;
        description = desc;
        vendor = vend;
        product = prod;
        os_type = os;
        severity = sev;
        cvss = cvss_input;
    }
};

//takes in cve_id_map and empty cvss_ordered_map passed by reference to update original values
//increments through every key in the cve_id_map and adds it to the multimap, which automatically sorts it upon insertion into a tree
//the data is added and sorted by cvss score (and can have duplicates due to it being a multimap)
void multimap_add_and_sort(unordered_map<string, DataTable> &input_map, multimap<float, string, greater<>> &multimap_to_fill)
{
    for (const auto& [key, data] : input_map) {
        multimap_to_fill.insert({data.cvss, key});
    }
}

//increment through each cvss value in the multimap
void multimap_print_all_cvss_ordered(unordered_map<string, DataTable> &unordered_map, multimap<float, string, greater<>> &multimap)
{
    cout << "sorted by CVSS score in descending order" << endl;
    for (const auto& [cvss, key] : multimap) {
        const DataTable& table_reference = unordered_map[key];
        std::cout << key << " -> cvss_score: " << table_reference.cvss << endl;
    }
}

//increment through each cvss value in the multimap based off some key_input parameter
void multimap_print_by_input(unordered_map<string, DataTable> &unordered_map, multimap<float, string, greater<>> &multimap, string key_var, string key_exact)
{
    int counter = 0;
    for(const auto& [cvss, key] : multimap)
    {
        const DataTable& table_reference = unordered_map[key];
        if (key_var == "published_date") {
            if(table_reference.published_date == key_exact)
            {
                cout << key << " -> " << table_reference.cvss << " -> " << table_reference.published_date << endl;
                counter++;
            }
        } else if (key_var == "vendor") {
            if(table_reference.vendor == key_exact)
            {
                cout << key << " -> " << table_reference.cvss << " -> " << table_reference.vendor << endl;
                counter++;
            }
        } else if (key_var == "product") {
            if(table_reference.product == key_exact)
            {
                cout << key << " -> " << table_reference.cvss << " -> " << table_reference.product << endl;
                counter++;
            }
        } else if (key_var == "os_type") {
            if(table_reference.os_type == key_exact)
            {
                cout << key << " -> " << table_reference.cvss << " -> " << table_reference.os_type << endl;
                counter++;
            }
        } else if (key_var == "severity") {
            if(table_reference.severity == key_exact)
            {
                cout << key << " -> " << table_reference.cvss << " -> " << table_reference.severity << endl;
                counter++;
            }
        } else if (key_var == "cvss") {
            if(table_reference.cvss == stof(key_exact))
            {
                cout << key << " -> " << table_reference.cvss << endl;
                counter++;
            }
        } else {
            cout << "please input valid type" << endl;
        }
    }
    cout << "total search hits: " << counter;
}


int main()
{
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

    multimap_add_and_sort(cve_id_map, cvss_ordered_map);
    multimap_print_all_cvss_ordered(cve_id_map, cvss_ordered_map);
    cout << endl;
    multimap_print_by_input(cve_id_map, cvss_ordered_map, "severity", "high");
    return 0;
}
