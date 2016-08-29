/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the blowfish symmetric encryption algorithm.
**/

#include "blowfish.h"
#include "stdio.h"

void test_schneier()
{
    struct blowfish bf;
    size_t i = 0;
    uint32_t key[34][2] = {
        {0x00000000, 0x00000000},
        {0xFFFFFFFF, 0xFFFFFFFF},
        {0x30000000, 0x00000000},
        {0x11111111, 0x11111111},
        {0x01234567, 0x89ABCDEF},
        {0x11111111, 0x11111111},
        {0x00000000, 0x00000000},
        {0xFEDCBA98, 0x76543210},
        {0x7CA11045, 0x4A1A6E57},
        {0x0131D961, 0x9DC1376E},
        {0x07A1133E, 0x4A0B2686},
        {0x3849674C, 0x2602319E},
        {0x04B915BA, 0x43FEB5B6},
        {0x0113B970, 0xFD34F2CE},
        {0x0170F175, 0x468FB5E6},
        {0x43297FAD, 0x38E373FE},
        {0x07A71370, 0x45DA2A16},
        {0x04689104, 0xC2FD3B2F},
        {0x37D06BB5, 0x16CB7546},
        {0x1F08260D, 0x1AC2465E},
        {0x58402364, 0x1ABA6176},
        {0x02581616, 0x4629B007},
        {0x49793EBC, 0x79B3258F},
        {0x4FB05E15, 0x15AB73A7},
        {0x49E95D6D, 0x4CA229BF},
        {0x018310DC, 0x409B26D6},
        {0x1C587F1C, 0x13924FEF},
        {0x01010101, 0x01010101},
        {0x1F1F1F1F, 0x0E0E0E0E},
        {0xE0FEE0FE, 0xF1FEF1FE},
        {0x00000000, 0x00000000},
        {0xFFFFFFFF, 0xFFFFFFFF},
        {0x01234567, 0x89ABCDEF},
        {0xFEDCBA98, 0x76543210}
    };
    uint32_t plaintext[34][2] = {
        {0x00000000, 0x00000000},
        {0xFFFFFFFF, 0xFFFFFFFF},
        {0x10000000, 0x00000001},
        {0x11111111, 0x11111111},
        {0x11111111, 0x11111111},
        {0x01234567, 0x89ABCDEF},
        {0x00000000, 0x00000000},
        {0x01234567, 0x89ABCDEF},
        {0x01A1D6D0, 0x39776742},
        {0x5CD54CA8, 0x3DEF57DA},
        {0x0248D438, 0x06F67172},
        {0x51454B58, 0x2DDF440A},
        {0x42FD4430, 0x59577FA2},
        {0x059B5E08, 0x51CF143A},
        {0x0756D8E0, 0x774761D2},
        {0x762514B8, 0x29BF486A},
        {0x3BDD1190, 0x49372802},
        {0x26955F68, 0x35AF609A},
        {0x164D5E40, 0x4F275232},
        {0x6B056E18, 0x759F5CCA},
        {0x004BD6EF, 0x09176062},
        {0x480D3900, 0x6EE762F2},
        {0x437540C8, 0x698F3CFA},
        {0x072D43A0, 0x77075292},
        {0x02FE5577, 0x8117F12A},
        {0x1D9D5C50, 0x18F728C2},
        {0x30553228, 0x6D6F295A},
        {0x01234567, 0x89ABCDEF},
        {0x01234567, 0x89ABCDEF},
        {0x01234567, 0x89ABCDEF},
        {0xFFFFFFFF, 0xFFFFFFFF},
        {0x00000000, 0x00000000},
        {0x00000000, 0x00000000},
        {0xFFFFFFFF, 0xFFFFFFFF}
    };

    uint32_t ciphertext[34][2] = {
        {0x4EF99745, 0x6198DD78},
        {0x51866FD5, 0xB85ECB8A},
        {0x7D856F9A, 0x613063F2},
        {0x2466DD87, 0x8B963C9D},
        {0x61F9C380, 0x2281B096},
        {0x7D0CC630, 0xAFDA1EC7},
        {0x4EF99745, 0x6198DD78},
        {0x0ACEAB0F, 0xC6A0A28D},
        {0x59C68245, 0xEB05282B},
        {0xB1B8CC0B, 0x250F09A0},
        {0x1730E577, 0x8BEA1DA4},
        {0xA25E7856, 0xCF2651EB},
        {0x353882B1, 0x09CE8F1A},
        {0x48F4D088, 0x4C379918},
        {0x432193B7, 0x8951FC98},
        {0x13F04154, 0xD69D1AE5},
        {0x2EEDDA93, 0xFFD39C79},
        {0xD887E039, 0x3C2DA6E3},
        {0x5F99D04F, 0x5B163969},
        {0x4A057A3B, 0x24D3977B},
        {0x452031C1, 0xE4FADA8E},
        {0x7555AE39, 0xF59B87BD},
        {0x53C55F9C, 0xB49FC019},
        {0x7A8E7BFA, 0x937E89A3},
        {0xCF9C5D7A, 0x4986ADB5},
        {0xD1ABB290, 0x658BC778},
        {0x55CB3774, 0xD13EF201},
        {0xFA34EC48, 0x47B268B2},
        {0xA7907951, 0x08EA3CAE},
        {0xC39E072D, 0x9FAC631D},
        {0x014933E0, 0xCDAFF6E4},
        {0xF21E9A77, 0xB71C49BC},
        {0x24594688, 0x5754369A},
        {0x6B5C5A9C, 0x5D9E0A5A}
    };

    for (i = 0; i < 34; i++) {
        blowfish_init(&bf, (uint32_t*) &key[i], 2);
        blowfish_encrypt(&bf, &plaintext[i][0], &plaintext[i][1]);
        printf("Test i: %zu\n", i);
        printf("Actual:   %08x,%08x\n", plaintext[i][0],  plaintext[i][1]);
        printf("Expected: %08x,%08x\n\n", ciphertext[i][0], ciphertext[i][1]);
    }
}

int main()
{
    test_schneier();
    return 0;
}
