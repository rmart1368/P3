cmake_minimum_required(VERSION 3.28)
project(P3Hashmap)

set(CMAKE_CXX_STANDARD 17)

add_executable(P3Hashmap main.cpp
        VulnerabilityMapper.cpp
        VulnerabilityMapper.h
        DataTable.h
        DataTable.cpp
        VulnerabilityInverseSetMapper.cpp
        VulnerabilityInverseSetMapper.h)
