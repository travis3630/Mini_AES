# include "MiniAES.h"
#include <iostream>

using namespace std;

int main()
{
    uint16_t key = 0b1101010110010111;
    Mini_AES A(key);
    while(true)
    {
        string input;
        cout << "Type Your Message: ";
        cin >> input;
        cout <<endl;
        // string num = "ewrmopbmqogpqwmgm29j90qjewfvascA">":L<{POK)_#KTKQ_kf-123tegewrfqweftgwq4t";
        // cout<< "decrypt message = ";
        vec_string c_text = A.encrypt(input);
        A.print_encrypted(c_text);
        string decrypted = A.decrypt(c_text);
        cout << "Your Decrypted Message: " << decrypted << endl << endl <<endl;
    }
    return 0;
}