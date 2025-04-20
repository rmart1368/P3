//
// Created by Trevor on 4/19/2025.
//
#include <string>
#ifndef P3HASHMAP_DATATABLE_H
#define P3HASHMAP_DATATABLE_H

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

    DataTable();
    DataTable(string date, string desc, string vend, string prod, string os, string sev, float cvss_input);
};
#endif //P3HASHMAP_DATATABLE_H
