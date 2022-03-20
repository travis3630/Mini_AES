#include "MiniAES.h"
#include <inttypes.h>


using namespace std;

uint8_t gal_add(uint8_t a, uint8_t b)
{
    //galois field addition in GF2^4
    return (a^b);
}

uint8_t gal_mul(uint8_t a, uint8_t b)
{
    //galois field multiplication in GF2^4
    uint8_t prime = 0b10011; //only primitives P(x)
    //Using Peasant Algorithm
    //Source: https://en.wikipedia.org/wiki/Multiplication_algorithm#Binary_or_Peasant_multiplication
    uint8_t rem = 0;
    for (; b; b >>= 1) {
        if (b & 1)
            rem ^= a;
        if (a & 0b1000)
            a = (a << 1) ^ prime;
        else
            a <<= 1;
    }
    return rem;
}

Mini_AES::Mini_AES(uint16_t _key)
{
    setsmap();
    key_schedule(_key);
}

void Mini_AES::setsmap()
{
    s_box.insert(pair<uint8_t,uint8_t>(0b0000,0b1110));
    s_box.insert(pair<uint8_t,uint8_t>(0b0001,0b0100));
    s_box.insert(pair<uint8_t,uint8_t>(0b0010,0b1101));
    s_box.insert(pair<uint8_t,uint8_t>(0b0011,0b0001));
    s_box.insert(pair<uint8_t,uint8_t>(0b0100,0b0010));
    s_box.insert(pair<uint8_t,uint8_t>(0b0101,0b1111));
    s_box.insert(pair<uint8_t,uint8_t>(0b0110,0b1011));
    s_box.insert(pair<uint8_t,uint8_t>(0b0111,0b1000));
    s_box.insert(pair<uint8_t,uint8_t>(0b1000,0b0011));
    s_box.insert(pair<uint8_t,uint8_t>(0b1001,0b1010));
    s_box.insert(pair<uint8_t,uint8_t>(0b1010,0b0110));
    s_box.insert(pair<uint8_t,uint8_t>(0b1011,0b1100));
    s_box.insert(pair<uint8_t,uint8_t>(0b1100,0b0101));
    s_box.insert(pair<uint8_t,uint8_t>(0b1101,0b1001));
    s_box.insert(pair<uint8_t,uint8_t>(0b1110,0b0000));
    s_box.insert(pair<uint8_t,uint8_t>(0b1111,0b0111));
    // inverse map of s_map
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1110,0b0000)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0100,0b0001)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1101,0b0010)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0001,0b0011)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0010,0b0100)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1111,0b0101)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1011,0b0110)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1000,0b0111)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0011,0b1000)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1010,0b1001)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0110,0b1010)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1100,0b1011)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0101,0b1100)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b1001,0b1101)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0000,0b1110)); // ok
    inverse_s_box.insert(pair<uint8_t,uint8_t>(0b0111,0b1111)); // ok
}

void Mini_AES::key_schedule(uint16_t _key)
{
    key = uinttoblock(_key);
    uint8_t rcon[2];
    rcon[0] = 0b0001;
    rcon[1] = 0b0010;
    round_key[0] = key;
    for (uint8_t r = 1; r<3; r++)
    {
        round_key[r][0][0] = gal_add(gal_add(round_key[r-1][0][0], s_box[round_key[r-1][1][1]]),rcon[r-1]);
        round_key[r][1][0] = gal_add(round_key[r-1][1][0],round_key[r][0][0]);
        round_key[r][0][1] = gal_add(round_key[r-1][0][1],round_key[r][1][0]);
        round_key[r][1][1] = gal_add(round_key[r-1][1][1],round_key[r][0][1]);
    }
}

cipher_block Mini_AES::uinttoblock(uint16_t _msg)
{
    cipher_block block;
    uint8_t one_nibb = 0b1111;
    block[0][0] = (_msg>>12)&one_nibb;
    block[1][0] = (_msg>>8)&one_nibb;
    block[0][1] = (_msg>>4)&one_nibb;
    block[1][1] = _msg&one_nibb;
    return block;
}

uint16_t Mini_AES::blocktouint(cipher_block _msg)
{
    uint16_t message = 0;
    for(auto i=0;i<2;i++)
    {
        for (auto j=0; j<2; j++)
        {
            message = message << 4;
            message |= _msg[j][i];
        }
    }
    return message;
}

vec_string Mini_AES::s2svec(string _msg)     /// ok!
{
    vec_string output;
    uint8_t slice_len = 2; // 1 char = 1 byte, 2 char = 2bytes = 16bits..
    for(auto i=0; i<_msg.length(); i+=slice_len)
    {
        uint16_t two_bytes = 0;
        uint16_t byte1 = static_cast<uint16_t> (_msg[i]);
        uint16_t byte2 = static_cast<uint16_t> (_msg[i+1]);
        two_bytes |= byte1;
        two_bytes = two_bytes <<8;
        two_bytes |= byte2;
        output.push_back( two_bytes );
        // cout << hex <<(output[i/2])<<endl;
        // cout << bitset<16>(output[i/2])<<endl;
    }
    return output;
}

string Mini_AES::svec2s(vec_string _msg)     ///ok!
{
    string text;
    for(auto i=0; i<_msg.size();i++)
    {
        uint8_t char1,char2;
        char2 = _msg[i] & 0xFF;
        _msg[i] = _msg[i] >> 8;
        char1 = _msg[i] & 0xFF;
        text.push_back(char1);
        text.push_back(char2);
    }
    // cout << text <<endl;
    return text;
}

cipher_block Mini_AES::nibblesub(cipher_block _block,bool inverse = false)
{
    map <uint8_t,uint8_t> lookup = inverse? inverse_s_box:s_box;
    for(uint8_t i=0;i<_block.size();i++)
    {
        for(uint8_t j=0;j<_block[i].size();j++)
        {
            _block[i][j] = lookup[_block[i][j]];
        }
    }
    return _block;
}

cipher_block Mini_AES::shiftrow(cipher_block _input)
{
    uint8_t temp = _input[1][1];
    _input[1][1] = _input[1][0];
    _input[1][0] = temp;
    return _input;
}

cipher_block Mini_AES::mixcol(cipher_block _input)
{
    cipher_block out;
    out[0][0] = gal_add(gal_mul(0b11,_input[0][0]),gal_mul(0b10,_input[1][0]));
    out[1][0] = gal_add(gal_mul(0b10,_input[0][0]),gal_mul(0b11,_input[1][0]));
    out[0][1] = gal_add(gal_mul(0b11,_input[0][1]),gal_mul(0b10,_input[1][1]));
    out[1][1] = gal_add(gal_mul(0b10,_input[0][1]),gal_mul(0b11,_input[1][1]));
    return out;
}

cipher_block Mini_AES::keyaddition(cipher_block _input,cipher_block _curr_key)
{
    cipher_block output;
    for(uint8_t i = 0; i<2; i++)
    {
        for(uint8_t j = 0; j<2; j++)
        {
            output[i][j] = gal_add(_input[i][j],_curr_key[i][j]);
        }
    }
    return output;
}

vec_string Mini_AES::encrypt(string _ptext)
{
    // 0th round keyaddition
    // 1st round nibbsub -> shiftrow -> Mixcolumn -> keyaddition
    // last round nibbsub -> shiftrow -> keyaddition
    vec_string ctext;
    vec_string temp = s2svec(_ptext);
    for(uint64_t i=0; i<temp.size();i++)
    {
        cipher_block text = uinttoblock(temp[i]);
        // round 0th
        text = keyaddition(text,round_key[0]);
        // round 1st
        text = nibblesub(text);
        text = shiftrow(text);
        text = mixcol(text);
        text = keyaddition(text,round_key[1]);
        // round last
        text = nibblesub(text);
        text = shiftrow(text);
        text = keyaddition(text,round_key[2]);
        // push back cipher text
        ctext.push_back(blocktouint(text));
    }
    cout << "encrypted message: " << svec2s(ctext) << endl;
    return ctext;
}

string Mini_AES::decrypt(vec_string _ctext)
{
    vec_string temp;
    string p_text;
    // reverse process of encryption
    for(uint64_t i=0; i<_ctext.size(); i++)
    {
        cipher_block text = uinttoblock(_ctext[i]);

        // last round 
        text = keyaddition(text,round_key[2]);
        text = shiftrow(text);
        text = nibblesub(text, true);

        // 1st round 
        text = keyaddition(text,round_key[1]);
        text = mixcol(text);
        text = shiftrow(text);
        text = nibblesub(text, true);

        //0th round
        text = keyaddition(text, round_key[0]);

        temp.push_back(blocktouint(text));
    }
    p_text = svec2s(temp);
    cout<< "decrypted message:  " << p_text << endl;
    return p_text;
}

void Mini_AES::print_encrypted(vec_string _encrypted)
{
    cout << "Your Encrypted Message in Hex format: ";
    for(uint64_t i=0; i<_encrypted.size(); i++)
    {
        cout << hex << (_encrypted[i]);
    }
    cout << endl;
}
