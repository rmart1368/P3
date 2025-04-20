//
// Created by Trevor on 4/19/2025.
//

#include <string>
#include "DataTable.h"
using namespace std;

DataTable::DataTable()
{
    published_date = "0";
    description = "0";
    vendor = "0";
    product = "0";
    os_type = "0";
    severity = "0";
    cvss = 0.0f;
}

DataTable::DataTable(string date, string desc, string vend, string prod, string os, string sev, float cvss_input)
{
published_date = date;
description = desc;
vendor = vend;
product = prod;
os_type = os;
severity = sev;
cvss = cvss_input;
}