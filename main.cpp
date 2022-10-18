#include <iostream>
#include "auth.h"

int main() {
    std::string secret = "MZKU6MSIKZ3ESVBWIQ4HE5RUIU4VGVJX";
    auth::totpCode code = auth::generateToken(secret);
    std::cout << code.code << " Time remain:";
    std::cout << code.timeRemain << std::endl;



    return 0;
}
