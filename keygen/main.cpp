//
//  main.cpp
//  keygen
//
//  Created by Jeff Phillips on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <cmath>
#include <ctime>
#include "Timer.h"
#include "des.h"

using namespace std;

int main(int argc, char *argv[])
{
    //double start, stop, tick1, tick2;
    
    Timer t;
    ofstream myfile;
    
    // start timer
    t.start();
    
    
    myfile.open ("example.txt");
    myfile << "Writing this to a file.\n";
    myfile.close();
    
    t.stop();
    
    cout << CLOCKS_PER_SEC << endl;
    cout << CLK_TCK << endl;
    cout << clock()/CLOCKS_PER_SEC << endl;
    cout << t.getElapsedTimeInMilliSec();
    
    return 0;
}
