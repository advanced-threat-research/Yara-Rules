rule BlackMatter
{
    /*
    Rule to detect first version of BlackMatter
    */
    meta:
        author = "ATR McAfee"
    
    strings:
        $a = { 30 26 46 4B 85 DB 75 02 EB 15 C1 E8 10 30 06 46 4B 85 DB 75 02 EB 08 30 26 46 4B 85 DB 75 C8 }
    condition:
        uint16(0) == 0x5A4D and $a
}
