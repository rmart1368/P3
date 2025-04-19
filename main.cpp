#include <iostream>
#include <unordered_map>
#include <map>
#include <string>
#include <vector>

using namespace std;

struct DataTable
{
    string description;
    string published_date;
    int year_published;
    string os_type;
    string sw_type;
    string version;
    string severity;
    float cvss;

    DataTable()
    {
        description = "0";
        published_date = "0";
        year_published = 0;
        os_type = "0";
        sw_type = "0";
        version = "0";
        severity = "0";
        cvss = 0.0f;
    }

    DataTable(string desc, string date, int year, string os, string sw, string ver, string sev, float cvss_input)
    {
        description = desc;
        published_date = date;
        year_published = year;
        os_type = os;
        sw_type = sw;
        version = ver;
        severity = sev;
        cvss = cvss_input;
    }
};

//takes in cve_id_map and empty cvss_ordered_map passed by reference to update original values
//increments through every key in the cve_id_map and adds it to the multimap, which automatically sorts it upon insertion into a tree
//the data is added and sorted by cvss score (and can have duplicates due to it being a multimap)
void multimap_add_and_sort(unordered_map<string, DataTable> &input_map, multimap<float, string, greater<>> &map_to_fill)
{
    for (const auto& [key, data] : input_map) {
        map_to_fill.insert({data.cvss, key});
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

//increment through each cvss value in the multimap
//waiting for updated variable list to finish
//void multimap_print_by_input(unordered_map<string, DataTable> &unordered_map, multimap<float, string, greater<>> &multimap, string key_input)
//{
//}


int main()
{
    unordered_map<string, DataTable> cve_id_map;
    multimap<float, string, greater<>> cvss_ordered_map;

    //format key: cve_id  value: <description, published_date, year, os, software, version, severity, cvss>
    //format key: text    value: <string, string, int, string, string, string, string, float>
    //connections from PYTHONSQL --> hashmap database still needs to be implemented
    //will only have inputted values with appropriate search parameters, only need to input values into map and sort

    cve_id_map["3492A"] = {"Mango", "14/03/2018", 2002, "Linux", "Photoshop", "1.3", "high", 7.8f};
    cve_id_map["9417Z"] = {"Apple", "09/11/2022", 2011, "Windows", "Notepad++", "2.2", "medium", 4.1f};
    cve_id_map["2058R"] = {"Banana", "22/07/2001", 1995, "Mac OS", "Final Cut Pro", "2.1", "low", 2.6f};
    cve_id_map["8013K"] = {"Strawberry", "05/05/2015", 2020, "Linux", "GIMP", "1.0", "medium", 8.9f};
    cve_id_map["6742B"] = {"Peach", "31/08/2008", 2007, "Windows", "Excel", "1.8", "high", 9.4f};
    cve_id_map["1923X"] = {"Pineapple", "17/02/1999", 1999, "Mac OS", "iMovie", "2.4", "low", 3.7f};
    cve_id_map["5069T"] = {"Grape", "28/10/2010", 2005, "Linux", "Blender", "2.0", "high", 6.3f};
    cve_id_map["7630M"] = {"Kiwi", "04/01/2021", 2021, "Windows", "Visual Studio", "1.5", "medium", 5.2f};
    cve_id_map["3985N"] = {"Orange", "11/12/1995", 1993, "Mac OS", "GarageBand", "2.5", "low", 1.9f};
    cve_id_map["5847L"] = {"Blueberry", "19/06/2012", 2016, "Linux", "Inkscape", "1.9", "medium", 9.0f};


    multimap_add_and_sort(cve_id_map, cvss_ordered_map);
    multimap_print_all_cvss_ordered(cve_id_map, cvss_ordered_map);

    return 0;
}
