#include <iostream>
#include <cassert>
#include "sha_hash.h"

using namespace std;

int main()
{

    sha_hash example;

    {
        assert((example("") == string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")));
        assert((example("The quick brown fox jumps over the lazy dog") == string("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")));
    }

    cout << "WHAT STRING DO YOU WANT TO HASH?\n"
         << "> ";

    string s{};
    getline (cin, s);

    cout << "Your hash is :\n"
         << example(s) << '\n';

    cout << "Enter something to end this programm:\n"
         << "> ";

    char c {};
    cin >> c;

    return 0;
}
