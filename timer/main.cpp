//
//  main.cpp
//  timer
//
//  Created by Jeff Phillips on 7/28/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

#include <iostream>
#include <cmath>
#include <ctime>
#include "Timer.h"
using namespace std;

int main(int argc, const char * argv[])
{

    double tick1, tick2;
    
    // first, use std clock() function to measure elapsed time ////////////////
    tick1 = tick2 = (double)clock(); // start timer and remember initial ticks
    
    // <Deleted code> //
    
    // second, use Timer::getElapsedTime() ////////////////////////////////////
    Timer t;
    
    // start timer
    t.start();
    tick1 = tick2 = t.getElapsedTimeInMilliSec();
    
    while(t.getElapsedTime() < 1)       // loop for 1 sec
    {
        cout << (tick2 - tick1) << " ms." << endl;
        
        tick1 = tick2;
        tick2 = t.getElapsedTimeInMilliSec();
    }
    
    cout << CLOCKS_PER_SEC << endl;
    cout << CLK_TCK << endl;
    cout << clock()/CLOCKS_PER_SEC << endl;
    
    return 0;

}

