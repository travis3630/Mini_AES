#include <array>
#include <string>
#include <map>
#include <vector>
#include <bitset>
#include <iostream>

using namespace std;

typedef array< array<uint8_t,2>,2> cipher_block;
typedef vector<uint16_t> vec_string;

class Mini_AES {
    private:
        cipher_block key;
        array<cipher_block,3> round_key;
        map<uint8_t, uint8_t> s_box;
        map<uint8_t, uint8_t> inverse_s_box;
    public:
        Mini_AES() {};
        Mini_AES(uint16_t k);
        void setsmap();
        void key_schedule(uint16_t k);
        cipher_block uinttoblock(uint16_t _msg);
        uint16_t blocktouint(cipher_block _msg);
        vec_string s2svec(string _msg);
        string svec2s(vec_string _msg);
        cipher_block nibblesub(cipher_block _block, bool inverse);
        cipher_block shiftrow(cipher_block _block);
        cipher_block mixcol(cipher_block _block);
        cipher_block keyaddition(cipher_block _input,cipher_block _curr_key);
        vec_string encrypt(string _ptext);
        string decrypt(vec_string _ctext);
        void print_encrypted(vec_string _encrypted);
};