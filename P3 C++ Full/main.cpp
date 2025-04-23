#include <iostream>
#include <unordered_map>
#include <map>
#include <string>
#include <vector>
#include "VulnerabilityMapper.h"
#include "VulnerabilityInverseSetMapper.h"
#include "DataTable.h"
#include <chrono>
#include <fstream>
#include <sstream>
using namespace std;


int main()
{
    VulnerabilityMapper vul_map;
    VulnerabilityInverseSetMapper vul_inv_set_map;
    vector<string> user_filter_inputs;

    //PARSE FILE INPUT
    ifstream input_file("./cve_export.txt");
    string line;
    int line_counter = 0;
    while (getline(input_file, line)) {
        line_counter++;
        vector<string> data_vector;
        stringstream ss(line);
        string data_value;
        int input_counter = 0;
        while (getline(ss, data_value, '\t')) {
            if (input_counter == 6)
            {
                if(data_value == "n/a") data_value = "0";
            }
            data_vector.push_back(data_value);
            input_counter++;
        }
        vul_map.unordered_map_SQL_upload(data_vector);
        vul_inv_set_map.unordered_map_SQL_upload(data_vector);
    }
    input_file.close();
    cout << "Data Values Loaded: " << line_counter << endl;

    //PARSE USER INPUT
    string input;
    cout << "Welcome to the CVE manager! Please follow the upcoming prompts!" << endl;
    cout << "If you would not like to search by a given parameter, press enter to skip" << endl;
    cout << "\nPlease input the date you would like to search in YYYY-MM-DD format:";
    getline(cin, input);
    user_filter_inputs.push_back(input);
    cout << "current filters:";
    for(int i = 0; i < user_filter_inputs.size(); i++)
    {
        cout << " [" << user_filter_inputs.at(i) << "] ";
    }

    cout << "\nPlease input the vendor you would like to search for:";
    getline(cin, input);
    user_filter_inputs.push_back(input);
    cout << "current filters:";
    for(int i = 0; i < user_filter_inputs.size(); i++)
    {
        cout << " [" << user_filter_inputs.at(i) << "] ";
    }
    cout << "\nPlease input the product you would like to search for:";
    getline(cin, input);
    user_filter_inputs.push_back(input);
    cout << "current filters:";
    for(int i = 0; i < user_filter_inputs.size(); i++)
    {
        cout << " [" << user_filter_inputs.at(i) << "] ";
    }

    cout << "\nPlease input the OS you would like to search for:";
    getline(cin, input);
    user_filter_inputs.push_back(input);
    cout << "current filters:";
    for(int i = 0; i < user_filter_inputs.size(); i++)
    {
        cout << " [" << user_filter_inputs.at(i) << "] ";
    }
    cout << "\nPlease input the Severity you would like to search for [LOW/MEDIUM/HIGH/CRITICAL]:";
    getline(cin, input);
    user_filter_inputs.push_back(input);
    cout << "current filters:";
    for(int i = 0; i < user_filter_inputs.size(); i++)
    {
        cout << " [" << user_filter_inputs.at(i) << "] ";
    }
    cout << endl << endl;

    //START OF FIRST ALGORITHM SEARCH AND FILTER TIMER
    auto start1 = std::chrono::high_resolution_clock::now();

    vul_map.multimap_add_and_sort();
    vul_map.multimap_print_by_input(user_filter_inputs.at(0), user_filter_inputs.at(1), user_filter_inputs.at(2), user_filter_inputs.at(3), user_filter_inputs.at(4));

    const auto finish1{chrono::high_resolution_clock::now()};
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(finish1 - start1);
    cout << "ALGO 1 TIME TAKEN: " << duration1.count() << " microseconds" << endl;

    cout << endl;

    //START OF SECOND ALGORITHM SEARCH AND FILTER TIMER
    auto start2 = std::chrono::high_resolution_clock::now();

    vul_inv_set_map.set_and_multimap_add_and_sort();
    vul_inv_set_map.set_and_multimap_print_by_input(user_filter_inputs.at(0), user_filter_inputs.at(1), user_filter_inputs.at(2), user_filter_inputs.at(3), user_filter_inputs.at(4));

    const auto finish2{chrono::high_resolution_clock::now()};
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(finish2 - start2);
    cout << "ALGO 2 TIME TAKEN: " << duration2.count() << " microseconds" << endl;

    return 0;
}
