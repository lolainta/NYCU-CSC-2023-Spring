#include<iostream>

using namespace std;

int main(int argc,char**argv){
    srand(stoi(argv[1]));
    cout<<rand()<<endl;
    return 0;
}
