use phf::phf_map;

// This is used for resolving Product IDs from hex values in the PE's Rich Header.
// Resource: https://github.com/dishather/richprint/blob/master/comp_id.txt
pub static MAP_PRODUCT_ID_AND_VS_VERSION: phf::Map<&'static str, (&'static str, &'static str)> = phf_map! {
    "0000" => ("???", "???"),
    "0001" => ("Import0", "Import0"),
    "0002" => ("Linker510", "VS97 (5.10)"),
    "0003" => ("Cvtomf510", "VS97 (5.10) "),
    "0004" => ("Linker600", "VS98 (6.0) "),
    "0005" => ("Cvtomf600", "VS98 (6.0)"),
    "0006" => ("Cvtres500", "VS97 (5.0)"),
    "0007" => ("Utc11_Basic", "VS97 (5.0)"),
    "0008" => ("Utc11_C", "VS97 (5.0)"),
    "0009" => ("Utc12_Basic", "VS98 (6.0)"),
    "000a" => ("Utc12_C", "VS98 (6.0)"),
    "000b" => ("Utc12_CPP", "VS98 (6.0)"),
    "000c" => ("AliasObj60", "VS98 (6.0)"),
    "000d" => ("VisualBasic60", "VS98 (6.0)"),
    "000e" => ("Masm613", "VS98 (6.13)"),
    "000f" => ("Masm710", "VS2003 (7.10)"),
    "0010" => ("Linker510", "VS97 (5.11)"),
    "0011" => ("Cvtomf511", "VS97 (5.11)"),
    "0012" => ("Masm614", "VS98 (6.14)"),
    "0013" => ("Linker512", "VS97 (5.12)"),
    "0014" => ("Cvtomf512", "VS97 (5.12)"),
    "0015" => ("Utc12_C_Std", "VS98 (6.0)"),
    "0016" => ("Utc12_CPP_Std", "VS98 (6.0)"),
    "0017" => ("Utc12_C_Book", "VS98 (6.0)"),
    "0018" => ("Utc12_CPP_Book", "VS98 (6.0)"),
    "0019" => ("Implib700", "VS2002 (7.0)"),
    "001a" => ("Cvtomf700", "VS2002 (7.0)"),
    "001b" => ("Utc13_Basic", "VS2002 (7.0)"),
    "001c" => ("Utc13_C", "VS2002 (7.0)"),
    "001d" => ("Utc13_CPP", "VS2002 (7.0) "),
    "001e" => ("Linker610", "VS98 (6.10)"),
    "001f" => ("Cvtomf610", "VS98 (6.10)"),
    "0020" => ("Linker601", "VS98 (6.01)"),
    "0021" => ("Cvtomf601", "VS98 (6.01)"),
    "0022" => ("Utc12_1_Basic", "VS98 (6.10)"),
    "0023" => ("Utc12_1_C", "VS98 (6.10)"),
    "0024" => ("Utc12_1_CPP", "VS98 (6.10)"),
    "0025" => ("Linker620", "VS98 (6.02)"),
    "0026" => ("Cvtomf620", "VS98 (6.02)"),
    "0027" => ("AliasObj70", "VS2002 (7.0)"),
    "0028" => ("Linker621", "VS98 (6.21)"),
    "0029" => ("Cvtomf621", "VS98 (6.21)"),
    "002a" => ("Masm615", "VS98 (6.15)"),
    "002b" => ("Utc13_LTCG_C", "VS2002 (7.0)"),
    "002c" => ("Utc13_LTCG_CPP", "VS2002 (7.0) "),
    "002d" => ("Masm620", "VS98 (6.20)"),
    "002e" => ("ILAsm100", "VS98 (6.20)"),
    "002f" => ("Utc12_2_Basic", "VS98 (6.20)"),
    "0030" => ("Utc12_2_C", "VS98 (6.20)"),
    "0031" => ("Utc12_2_CPP", "VS98 (6.20)"),
    "0032" => ("Utc12_2_C_Std", "VS98 (6.20)"),
    "0033" => ("Utc12_2_CPP_Std", "VS98 (6.20)"),
    "0034" => ("Utc12_2_C_Book", "VS98 (6.20)"),
    "0035" => ("Utc12_2_CPP_Book", "VS98 (6.20)"),
    "0036" => ("Implib622", "VS98 (6.22)"),
    "0037" => ("Cvtomf622", "VS98 (6.22)"),
    "0038" => ("Cvtres501", "VS97 (5.01)"),
    "0039" => ("Utc13_C_Std", "VS2002 (7.0)"),
    "003a" => ("Utc13_CPP_Std", "VS2002 (7.0)"),
    "003b" => ("Cvtpgd1300", "VS2002 (7.0)"),
    "003c" => ("Linker622", "VS98 (6.22)"),
    "003d" => ("Linker700", "VS2002 (7.0)"),
    "003e" => ("Export622", "VS98 (6.22)"),
    "003f" => ("Export700", "VS2002 (7.0)"),
    "0040" => ("Masm700", "VS2002 (7.0)"),
    "0041" => ("Utc13_POGO_I_C", "VS2002 (7.0)"),
    "0042" => ("Utc13_POGO_I_CPP", "VS2002 (7.0)"),
    "0043" => ("Utc13_POGO_O_C", "VS2002 (7.0)"),
    "0044" => ("Utc13_POGO_O_CPP", "VS2002 (7.0)"),
    "0045" => ("Cvtres700", "VS2002 (7.0)"),
    "0046" => ("Cvtres710p", "VS2003 (7.10p)"),
    "0047" => ("Linker710p", "VS2003 (7.10p)"),
    "0048" => ("Cvtomf710p", "VS2003 (7.10p)"),
    "0049" => ("Export710p", "VS2003 (7.10p)"),
    "004a" => ("Implib710p", "VS2003 (7.10p)"),
    "004b" => ("Masm710p", "VS2003 (7.10p)"),
    "004c" => ("Utc1310p_C", "VS2003 (7.10p)"),
    "004d" => ("Utc1310p_CPP", "VS2003 (7.10p)"),
    "004e" => ("Utc1310p_C_Std", "VS2003 (7.10p)"),
    "004f" => ("Utc1310p_CPP_Std", "VS2003 (7.10p)"),
    "0050" => ("Utc1310p_LTCG_C", "VS2003 (7.10p)"),
    "0051" => ("Utc1310p_LTCG_CPP", "VS2003 (7.10p)"),
    "0052" => ("Utc1310p_POGO_I_C", "VS2003 (7.10p)"),
    "0053" => ("Utc1310p_POGO_I_CPP", "VS2003 (7.10p)"),
    "0054" => ("Utc1310p_POGO_O_C", "VS2003 (7.10p)"),
    "0055" => ("Utc1310p_POGO_O_CPP", "VS2003 (7.10p)"),
    "0056" => ("Linker624", "VS98 (6.24)"),
    "0057" => ("Cvtomf624", "VS98 (6.24)"),
    "0058" => ("Export624", "VS98 (6.24)"),
    "0059" => ("Implib624", "VS98 (6.24)"),
    "005a" => ("Linker710", "VS2003 (7.10)"),
    "005b" => ("Cvtomf710", "VS2003 (7.10)"),
    "005c" => ("Export710", "VS2003 (7.10)"),
    "005d" => ("Implib710", "VS2003 (7.10)"),
    "005e" => ("Cvtres710", "VS2003 (7.10)"),
    "005f" => ("Utc1310_C", "VS2003 (7.10)"),
    "0060" => ("Utc1310_CPP", "VS2003 (7.10)"),
    "0061" => ("Utc1310_C_Std", "VS2003 (7.10)"),
    "0062" => ("Utc1310_CPP_Std", "VS2003 (7.10)"),
    "0063" => ("Utc1310_LTCG_C", "VS2003 (7.10)"),
    "0064" => ("Utc1310_LTCG_CPP", "VS2003 (7.10)"),
    "0065" => ("Utc1310_POGO_I_C", "VS2003 (7.10)"),
    "0066" => ("Utc1310_POGO_I_CPP", "VS2003 (7.10)"),
    "0067" => ("Utc1310_POGO_O_C", "VS2003 (7.10)"),
    "0068" => ("Utc1310_POGO_O_CPP", "VS2003 (7.10)"),
    "0069" => ("AliasObj710", "VS2003 (7.10)"),
    "006a" => ("AliasObj710p", "VS2003 (7.10p)"),
    "006b" => ("Cvtpgd1310", "VS2003 (7.10)"),
    "006c" => ("Cvtpgd1310p", "VS2003 (7.10p)"),
    "006d" => ("Utc1400_C", "VS2005 (8.0)"),
    "006e" => ("Utc1400_CPP", "VS2005 (8.0)"),
    "006f" => ("Utc1400_C_Std", "VS2005 (8.0)"),
    "0070" => ("Utc1400_CPP_Std", "VS2005 (8.0)"),
    "0071" => ("Utc1400_LTCG_C", "VS2005 (8.0)"),
    "0072" => ("Utc1400_LTCG_CPP", "VS2005 (8.0)"),
    "0073" => ("Utc1400_POGO_I_C", "VS2005 (8.0)"),
    "0074" => ("Utc1400_POGO_I_CPP", "VS2005 (8.0)"),
    "0075" => ("Utc1400_POGO_O_C", "VS2005 (8.0)"),
    "0076" => ("Utc1400_POGO_O_CPP", "VS2005 (8.0)"),
    "0077" => ("Cvtpgd1400", "VS2005 (8.0)"),
    "0078" => ("Linker800", "VS2005 (8.0)"),
    "0079" => ("Cvtomf800", "VS2005 (8.0)"),
    "007a" => ("Export800", "VS2005 (8.0)"),
    "007b" => ("Implib800", "VS2005 (8.0)"),
    "007c" => ("Cvtres800", "VS2005 (8.0)"),
    "007d" => ("Masm800", "VS2005 (8.0)"),
    "007e" => ("AliasObj800", "VS2005 (8.0)"),
    "007f" => ("PhoenixPrerelease", "Phoenix Prerelease"),
    "0080" => ("Utc1400_CVTCIL_C", "VS2005 (8.0)"),
    "0081" => ("Utc1400_CVTCIL_CPP", "VS2005 (8.0)"),
    "0082" => ("Utc1400_LTCG_MSIL", "VS2005 (8.0)"),
    "0083" => ("Utc1500_C", "VS2008 (9.0)"),
    "0084" => ("Utc1500_CPP", "VS2008 (9.0)"),
    "0085" => ("Utc1500_C_Std", "VS2008 (9.0)"),
    "0086" => ("Utc1500_CPP_Std", "VS2008 (9.0)"),
    "0087" => ("Utc1500_CVTCIL_C", "VS2008 (9.0)"),
    "0088" => ("Utc1500_CVTCIL_CPP", "VS2008 (9.0)"),
    "0089" => ("Utc1500_LTCG_C", "VS2008 (9.0)"),
    "008a" => ("Utc1500_LTCG_CPP", "VS2008 (9.0)"),
    "008b" => ("Utc1500_LTCG_MSIL", "VS2008 (9.0)"),
    "008c" => ("Utc1500_POGO_I_C", "VS2008 (9.0)"),
    "008d" => ("Utc1500_POGO_I_CPP", "VS2008 (9.0)"),
    "008e" => ("Utc1500_POGO_O_C", "VS2008 (9.0)"),
    "008f" => ("Utc1500_POGO_O_CPP", "VS2008 (9.0)"),
    "0090" => ("Cvtpgd1500", "VS2008 (9.0)"),
    "0091" => ("Linker900", "VS2008 (9.0)"),
    "0092" => ("Export900", "VS2008 (9.0)"),
    "0093" => ("Implib900", "VS2008 (9.0)"),
    "0094" => ("Cvtres900", "VS2008 (9.0)"),
    "0095" => ("Masm900", "VS2008 (9.0)"),
    "0096" => ("AliasObj900", "VS2008 (9.0)"),
    "0097" => ("Resource", "Resource"),
    "0098" => ("AliasObj1000", "VS2010 (10.0)"),
    "0099" => ("Cvtpgd1600", "VS2010 (10.0)"),
    "009a" => ("Cvtres1000", "VS2010 (10.0)"),
    "009b" => ("Export1000", "VS2010 (10.0)"),
    "009c" => ("Implib1000", "VS2010 (10.0)"),
    "009d" => ("Linker1000", "VS2010 (10.0)"),
    "009e" => ("Masm1000", "VS2010 (10.0)"),
    "009f" => ("Phx1600_C", "Phoenix (10.0)"),
    "00a0" => ("Phx1600_CPP", "Phoenix (10.0)"),
    "00a1" => ("Phx1600_CVTCIL_C", "Phoenix (10.0)"),
    "00a2" => ("Phx1600_CVTCIL_CPP", "Phoenix (10.0)"),
    "00a3" => ("Phx1600_LTCG_C", "Phoenix (10.0)"),
    "00a4" => ("Phx1600_LTCG_CPP", "Phoenix (10.0)"),
    "00a5" => ("Phx1600_LTCG_MSIL", "Phoenix (10.0)"),
    "00a6" => ("Phx1600_POGO_I_C", "Phoenix (10.0)"),
    "00a7" => ("Phx1600_POGO_I_CPP", "Phoenix (10.0)"),
    "00a8" => ("Phx1600_POGO_O_C", "Phoenix (10.0)"),
    "00a9" => ("Phx1600_POGO_O_CPP", "Phoenix (10.0)"),
    "00aa" => ("Utc1600_C", "VS2010 (10.0)"),
    "00ab" => ("Utc1600_CPP", "VS2010 (10.0)"),
    "00ac" => ("Utc1600_CVTCIL_C", "VS2010 (10.0)"),
    "00ad" => ("Utc1600_CVTCIL_CPP", "VS2010 (10.0)"),
    "00ae" => ("Utc1600_LTCG_C", "VS2010 (10.0)"),
    "00af" => ("Utc1600_LTCG_CPP", "VS2010 (10.0)"),
    "00b0" => ("Utc1600_LTCG_MSIL", "VS2010 (10.0)"),
    "00b1" => ("Utc1600_POGO_I_C", "VS2010 (10.0)"),
    "00b2" => ("Utc1600_POGO_I_CPP", "VS2010 (10.0)"),
    "00b3" => ("Utc1600_POGO_O_C", "VS2010 (10.0)"),
    "00b4" => ("Utv1600_POGO_O_CPP", "VS2010 (10.0)"),
    "00b5" => ("AliasObj1010", "VS2010 (10.10)"),
    "00b6" => ("Cvtpgd1610", "VS2010 (10.10)"),
    "00b7" => ("Cvtres1010", "VS2010 (10.10)"),
    "00b8" => ("Export1010", "VS2010 (10.10)"),
    "00b9" => ("Implib1010", "VS2010 (10.10)"),
    "00ba" => ("Linker1010", "VS2010 (10.10)"),
    "00bb" => ("Masm1010", "VS2010 (10.10)"),
    "00bc" => ("Utc1610_C", "VS2010 (10.10)"),
    "00bd" => ("Utc1610_CPP", "VS2010 (10.10)"),
    "00be" => ("Utc1610_CVTCIL_C", "VS2010 (10.10)"),
    "00bf" => ("Utc1610_CVTCIL_CPP", "VS2010 (10.10)"),
    "00c0" => ("Utc1610_LTCG_C", "VS2010 (10.10)"),
    "00c1" => ("Utc1610_LTCG_CPP", "VS2010 (10.10)"),
    "00c2" => ("Utc1610_LTCG_MSIL", "VS2010 (10.10)"),
    "00c3" => ("Utc1610_POGO_I_C", "VS2010 (10.10)"),
    "00c4" => ("Utc1610_POGO_I_CPP", "VS2010 (10.10)"),
    "00c5" => ("Utc1610_POGO_O_C", "VS2010 (10.10)"),
    "00c6" => ("Utc1610_POGO_O_CPP", "VS2010 (10.10)"),
    "00c7" => ("AliasObj1100", "VS2012 (11.0)"),
    "00c8" => ("Cvtpgd1700", "VS2012 (11.0)"),
    "00c9" => ("Cvtres1100", "VS2012 (11.0)"),
    "00ca" => ("Export1100", "VS2012 (11.0)"),
    "00cb" => ("Implib1100", "VS2012 (11.0)"),
    "00cc" => ("Linker1100", "VS2012 (11.0)"),
    "00cd" => ("Masm1100", "VS2012 (11.0)"),
    "00ce" => ("Utc1700_C", "VS2012 (11.0)"),
    "00cf" => ("Utc1700_CPP", "VS2012 (11.0)"),
    "00d0" => ("Utc1700_CVTCIL_C", "VS2012 (11.0)"),
    "00d1" => ("Utc1700_CVTCIL_CPP", "VS2012 (11.0)"),
    "00d2" => ("Utc1700_LTCG_C", "VS2012 (11.0)"),
    "00d3" => ("Utc1700_LTCG_CPP", "VS2012 (11.0)"),
    "00d4" => ("Utc1700_LTCG_MSIL", "VS2012 (11.0)"),
    "00d5" => ("Utc1700_POGO_I_C", "VS2012 (11.0)"),
    "00d6" => ("Utc1700_POGO_I_CPP", "VS2012 (11.0)"),
    "00d7" => ("Utc1700_POGO_O_C", "VS2012 (11.0)"),
    "00d8" => ("Utc1700_POGO_O_CPP", "VS2012 (11.0)"),
    "00d9" => ("AliasObj1200", "VS2013 (12.0)"),
    "00da" => ("Cvtpgd1800", "VS2013 (12.0)"),
    "00db" => ("Cvtres1200", "VS2013 (12.0)"),
    "00dc" => ("Export1200", "VS2013 (12.0)"),
    "00dd" => ("Implib1200", "VS2013 (12.0)"),
    "00de" => ("Linker1200", "VS2013 (12.0)"),
    "00df" => ("Masm1200", "VS2013 (12.0)"),
    "00e0" => ("Utc1800_C", "VS2013 (12.0)"),
    "00e1" => ("Utc1800_CPP", "VS2013 (12.0)"),
    "00e2" => ("Utc1800_CVTCIL_C", "VS2013 (12.0)"),
    "00e3" => ("Utc1800_CVTCIL_CPP", "VS2013 (12.0)"),
    "00e4" => ("Utc1800_LTCG_C", "VS2013 (12.0)"),
    "00e5" => ("Utc1800_LTCG_CPP", "VS2013 (12.0)"),
    "00e6" => ("Utc1800_LTCG_MSIL", "VS2013 (12.0)"),
    "00e7" => ("Utc1800_POGO_I_C", "VS2013 (12.0)"),
    "00e8" => ("Utc1800_POGO_I_CPP", "VS2013 (12.0)"),
    "00e9" => ("Utc1800_POGO_O_C", "VS2013 (12.0)"),
    "00ea" => ("Utc1800_POGO_O_CPP", "VS2013 (12.0)"),
    "00eb" => ("AliasObj1210", "VS2013 (12.10)"),
    "00ec" => ("Cvtpgd1810", "VS2013 (12.10)"),
    "00ed" => ("Cvtres1210", "VS2013 (12.10)"),
    "00ee" => ("Export1210", "VS2013 (12.10)"),
    "00ef" => ("Implib1210", "VS2013 (12.10)"),
    "00f0" => ("Linker1210", "VS2013 (12.10)"),
    "00f1" => ("Masm1210", "VS2013 (12.10)"),
    "00f2" => ("Utc1810_C", "VS2013 (12.10)"),
    "00f3" => ("Utc1810_CPP", "VS2013 (12.10)"),
    "00f4" => ("Utc1810_CVTCIL_C", "VS2013 (12.10)"),
    "00f5" => ("Utc1810_CVTCIL_CPP", "VS2013 (12.10)"),
    "00f6" => ("Utc1810_LTCG_C", "VS2013 (12.10)"),
    "00f7" => ("Utc1810_LTCG_CPP", "VS2013 (12.10)"),
    "00f8" => ("Utc1810_LTCG_MSIL", "VS2013 (12.10)"),
    "00f9" => ("Utc1810_POGO_I_C", "VS2013 (12.10)"),
    "00fa" => ("Utc1810_POGO_I_CPP", "VS2013 (12.10)"),
    "00fb" => ("Utc1810_POGO_O_C", "VS2013 (12.10)"),
    "00fc" => ("Utc1810_POGO_O_CPP", "VS2013 (12.10)"),
    "00fd" => ("AliasObj1400", "VS2015+ (14.0+)"),
    "00fe" => ("Cvtpgd1900", "VS2015+ (14.0+)"),
    "00ff" => ("Cvtres1400", "VS2015+ (14.0+)"),
    "0100" => ("Export1400", "VS2015+ (14.0+)"),
    "0101" => ("Implib1400", "VS2015+ (14.0+)"),
    "0102" => ("Linker1400", "VS2015+ (14.0+)"),
    "0103" => ("Masm1400", "VS2015+ (14.0+)"),
    "0104" => ("Utc1900_C", "VS2015+ (14.0+)"),
    "0105" => ("Utc1900_CPP", "VS2015+ (14.0+)"),
    "0106" => ("Utc1900_CVTCIL_C", "VS2015+ (14.0+)"),
    "0107" => ("Utc1900_CVTCIL_CPP", "VS2015+ (14.0+)"),
    "0108" => ("Utc1900_LTCG_C", "VS2015+ (14.0+)"),
    "0109" => ("Utc1900_LTCG_CPP", "VS2015+ (14.0+)"),
    "010a" => ("Utc1900_LTCG_MSIL", "VS2015+ (14.0+)"),
    "010b" => ("Utc1900_POGO_I_C", "VS2015+ (14.0+)"),
    "010c" => ("Utc1900_POGO_I_CPP", "VS2015+ (14.0+)"),
    "010d" => ("Utc1900_POGO_O_C", "VS2015+ (14.0+)"),
    "010e" => ("Utc1900_POGO_O_CPP", "VS2015+ (14.0+)"),
};

// These mappings are used for resolving functions from ordinals in the `hash_pe_imphash` function.
// Resources:
//  - https://gitlab.winehq.org/mjgarton/wine/-/raw/master/dlls/comctl32/comctl32.spec
//  - https://www.geoffchappell.com/studies/windows/shell/comctl32/history/ords610.htm?ta=7.6666717529296875&tx=3
pub static MAP_COMCTL32_ORDINAL: phf::Map<u16, &'static str> = phf_map! {
    2u16 => "MenuHelp",
    3u16 => "ShowHideMenuCtl",
    4u16 => "GetEffectiveClientRect",
    5u16 => "DrawStatusTextA",
    6u16 => "CreateStatusWindowA",
    7u16 => "CreateToolbar",
    8u16 => "CreateMappedBitmap",
    9u16 => "DPA_LoadStream",
    10u16 => "DPA_SaveStream",
    11u16 => "DPA_Merge",
    12u16 => "Cctl1632_ThunkData32",
    13u16 => "MakeDragList",
    14u16 => "LBItemFromPt",
    15u16 => "DrawInsert",
    16u16 => "CreateUpDownControl",
    17u16 => "InitCommonControls",
    71u16 => "Alloc",
    72u16 => "ReAlloc",
    73u16 => "Free",
    74u16 => "GetSize",
    151u16 => "CreateMRUListA",
    152u16 => "FreeMRUList",
    153u16 => "AddMRUStringA",
    154u16 => "EnumMRUListA",
    155u16 => "FindMRUStringA",
    156u16 => "ImageList_Create",
    157u16 => "CreateMRUListLazyA",
    163u16 => "CreatePage",
    164u16 => "CreateProxyPage",
    167u16 => "AddMRUData",
    169u16 => "FindMRUData",
    182u16 => "ImageList_ReplaceIcon",
    183u16 => "ImageList_SetBkColor",
    233u16 => "Str_GetPtrA",
    234u16 => "Str_SetPtrA",
    235u16 => "Str_GetPtrW",
    236u16 => "Str_SetPtrW",
    320u16 => "DSA_Create",
    321u16 => "DSA_Destroy",
    322u16 => "DSA_GetItem",
    323u16 => "DSA_GetItemPtr",
    324u16 => "DSA_InsertItem",
    325u16 => "DSA_SetItem",
    326u16 => "DSA_DeleteItem",
    327u16 => "DSA_DeleteAllItems",
    328u16 => "DPA_Create",
    329u16 => "DPA_Destroy",
    330u16 => "DPA_Grow",
    331u16 => "DPA_Clone",
    332u16 => "DPA_GetPtr",
    333u16 => "DPA_GetPtrIndex",
    334u16 => "DPA_InsertPtr",
    335u16 => "DPA_SetPtr",
    336u16 => "DPA_DeletePtr",
    337u16 => "DPA_DeleteAllPtrs",
    338u16 => "DPA_Sort",
    339u16 => "DPA_Search",
    340u16 => "DPA_CreateEx",
    341u16 => "SendNotify",
    342u16 => "SendNotifyEx",
    344u16 => "TaskDialog",
    345u16 => "TaskDialogIndirect",
    350u16 => "StrChrA",
    351u16 => "StrRChrA",
    352u16 => "StrCmpNA",
    353u16 => "StrCmpNIA",
    354u16 => "StrStrA",
    355u16 => "StrStrIA",
    356u16 => "StrCSpnA",
    357u16 => "StrToIntA",
    358u16 => "StrChrW",
    359u16 => "StrRChrW",
    360u16 => "StrCmpNW",
    361u16 => "StrCmpNIW",
    362u16 => "StrStrW",
    363u16 => "StrStrIW",
    364u16 => "StrCSpnW",
    365u16 => "StrToIntW",
    366u16 => "StrChrIA",
    367u16 => "StrChrIW",
    368u16 => "StrRChrIA",
    369u16 => "StrRChrIW",
    372u16 => "StrRStrIA",
    373u16 => "StrRStrIW",
    374u16 => "StrCSpnIA",
    375u16 => "StrCSpnIW",
    376u16 => "IntlStrEqWorkerA",
    377u16 => "IntlStrEqWorkerW",
    380u16 => "LoadIconMetric",
    381u16 => "LoadIconWithScaleDown",
    382u16 => "SmoothScrollWindow",
    383u16 => "DoReaderMode",
    384u16 => "SetPathWordBreakProc",
    385u16 => "DPA_EnumCallback",
    386u16 => "DPA_DestroyCallback",
    387u16 => "DSA_EnumCallback",
    388u16 => "DSA_DestroyCallback",
    389u16 => "SHGetProcessDword",
    390u16 => "ImageList_SetColorTable",
    400u16 => "CreateMRUListW",
    401u16 => "AddMRUStringW",
    402u16 => "FindMRUStringW",
    403u16 => "EnumMRUListW",
    404u16 => "CreateMRUListLazyW",
    410u16 => "SetWindowSubclass",
    411u16 => "GetWindowSubclass",
    412u16 => "RemoveWindowSubclass",
    413u16 => "DefSubclassProc",
    414u16 => "MirrorIcon",
    415u16 => "DrawTextWrap",
    416u16 => "DrawTextExPrivWrap",
    417u16 => "ExtTextOutWrap",
    418u16 => "GetCharWidthWrap",
    419u16 => "GetTextExtentPointWrap",
    420u16 => "GetTextExtentPoint32Wrap",
    421u16 => "TextOutWrap",
 };

// Resource: https://docs.rs/exe/latest/src/exe/imphash.rs.html#126
pub static MAP_OLEAUT32_ORDINAL: phf::Map<u16, &'static str> = phf_map! {
    2u16 => "SysAllocString",
    3u16 => "SysReAllocString",
    4u16 => "SysAllocStringLen",
    5u16 => "SysReAllocStringLen",
    6u16 => "SysFreeString",
    7u16 => "SysStringLen",
    8u16 => "VariantInit",
    9u16 => "VariantClear",
    10u16 => "VariantCopy",
    11u16 => "VariantCopyInd",
    12u16 => "VariantChangeType",
    13u16 => "VariantTimeToDosDateTime",
    14u16 => "DosDateTimeToVariantTime",
    15u16 => "SafeArrayCreate",
    16u16 => "SafeArrayDestroy",
    17u16 => "SafeArrayGetDim",
    18u16 => "SafeArrayGetElemsize",
    19u16 => "SafeArrayGetUBound",
    20u16 => "SafeArrayGetLBound",
    21u16 => "SafeArrayLock",
    22u16 => "SafeArrayUnlock",
    23u16 => "SafeArrayAccessData",
    24u16 => "SafeArrayUnaccessData",
    25u16 => "SafeArrayGetElement",
    26u16 => "SafeArrayPutElement",
    27u16 => "SafeArrayCopy",
    28u16 => "DispGetParam",
    29u16 => "DispGetIDsOfNames",
    30u16 => "DispInvoke",
    31u16 => "CreateDispTypeInfo",
    32u16 => "CreateStdDispatch",
    33u16 => "RegisterActiveObject",
    34u16 => "RevokeActiveObject",
    35u16 => "GetActiveObject",
    36u16 => "SafeArrayAllocDescriptor",
    37u16 => "SafeArrayAllocData",
    38u16 => "SafeArrayDestroyDescriptor",
    39u16 => "SafeArrayDestroyData",
    40u16 => "SafeArrayRedim",
    41u16 => "SafeArrayAllocDescriptorEx",
    42u16 => "SafeArrayCreateEx",
    43u16 => "SafeArrayCreateVectorEx",
    44u16 => "SafeArraySetRecordInfo",
    45u16 => "SafeArrayGetRecordInfo",
    46u16 => "VarParseNumFromStr",
    47u16 => "VarNumFromParseNum",
    48u16 => "VarI2FromUI1",
    49u16 => "VarI2FromI4",
    50u16 => "VarI2FromR4",
    51u16 => "VarI2FromR8",
    52u16 => "VarI2FromCy",
    53u16 => "VarI2FromDate",
    54u16 => "VarI2FromStr",
    55u16 => "VarI2FromDisp",
    56u16 => "VarI2FromBool",
    57u16 => "SafeArraySetIID",
    58u16 => "VarI4FromUI1",
    59u16 => "VarI4FromI2",
    60u16 => "VarI4FromR4",
    61u16 => "VarI4FromR8",
    62u16 => "VarI4FromCy",
    63u16 => "VarI4FromDate",
    64u16 => "VarI4FromStr",
    65u16 => "VarI4FromDisp",
    66u16 => "VarI4FromBool",
    67u16 => "SafeArrayGetIID",
    68u16 => "VarR4FromUI1",
    69u16 => "VarR4FromI2",
    70u16 => "VarR4FromI4",
    71u16 => "VarR4FromR8",
    72u16 => "VarR4FromCy",
    73u16 => "VarR4FromDate",
    74u16 => "VarR4FromStr",
    75u16 => "VarR4FromDisp",
    76u16 => "VarR4FromBool",
    77u16 => "SafeArrayGetVartype",
    78u16 => "VarR8FromUI1",
    79u16 => "VarR8FromI2",
    80u16 => "VarR8FromI4",
    81u16 => "VarR8FromR4",
    82u16 => "VarR8FromCy",
    83u16 => "VarR8FromDate",
    84u16 => "VarR8FromStr",
    85u16 => "VarR8FromDisp",
    86u16 => "VarR8FromBool",
    87u16 => "VarFormat",
    88u16 => "VarDateFromUI1",
    89u16 => "VarDateFromI2",
    90u16 => "VarDateFromI4",
    91u16 => "VarDateFromR4",
    92u16 => "VarDateFromR8",
    93u16 => "VarDateFromCy",
    94u16 => "VarDateFromStr",
    95u16 => "VarDateFromDisp",
    96u16 => "VarDateFromBool",
    97u16 => "VarFormatDateTime",
    98u16 => "VarCyFromUI1",
    99u16 => "VarCyFromI2",
    100u16 => "VarCyFromI4",
    101u16 => "VarCyFromR4",
    102u16 => "VarCyFromR8",
    103u16 => "VarCyFromDate",
    104u16 => "VarCyFromStr",
    105u16 => "VarCyFromDisp",
    106u16 => "VarCyFromBool",
    107u16 => "VarFormatNumber",
    108u16 => "VarBstrFromUI1",
    109u16 => "VarBstrFromI2",
    110u16 => "VarBstrFromI4",
    111u16 => "VarBstrFromR4",
    112u16 => "VarBstrFromR8",
    113u16 => "VarBstrFromCy",
    114u16 => "VarBstrFromDate",
    115u16 => "VarBstrFromDisp",
    116u16 => "VarBstrFromBool",
    117u16 => "VarFormatPercent",
    118u16 => "VarBoolFromUI1",
    119u16 => "VarBoolFromI2",
    120u16 => "VarBoolFromI4",
    121u16 => "VarBoolFromR4",
    122u16 => "VarBoolFromR8",
    123u16 => "VarBoolFromDate",
    124u16 => "VarBoolFromCy",
    125u16 => "VarBoolFromStr",
    126u16 => "VarBoolFromDisp",
    127u16 => "VarFormatCurrency",
    128u16 => "VarWeekdayName",
    129u16 => "VarMonthName",
    130u16 => "VarUI1FromI2",
    131u16 => "VarUI1FromI4",
    132u16 => "VarUI1FromR4",
    133u16 => "VarUI1FromR8",
    134u16 => "VarUI1FromCy",
    135u16 => "VarUI1FromDate",
    136u16 => "VarUI1FromStr",
    137u16 => "VarUI1FromDisp",
    138u16 => "VarUI1FromBool",
    139u16 => "VarFormatFromTokens",
    140u16 => "VarTokenizeFormatString",
    141u16 => "VarAdd",
    142u16 => "VarAnd",
    143u16 => "VarDiv",
    144u16 => "DllCanUnloadNow",
    145u16 => "DllGetClassObject",
    146u16 => "DispCallFunc",
    147u16 => "VariantChangeTypeEx",
    148u16 => "SafeArrayPtrOfIndex",
    149u16 => "SysStringByteLen",
    150u16 => "SysAllocStringByteLen",
    151u16 => "DllRegisterServer",
    152u16 => "VarEqv",
    153u16 => "VarIdiv",
    154u16 => "VarImp",
    155u16 => "VarMod",
    156u16 => "VarMul",
    157u16 => "VarOr",
    158u16 => "VarPow",
    159u16 => "VarSub",
    160u16 => "CreateTypeLib",
    161u16 => "LoadTypeLib",
    162u16 => "LoadRegTypeLib",
    163u16 => "RegisterTypeLib",
    164u16 => "QueryPathOfRegTypeLib",
    165u16 => "LHashValOfNameSys",
    166u16 => "LHashValOfNameSysA",
    167u16 => "VarXor",
    168u16 => "VarAbs",
    169u16 => "VarFix",
    170u16 => "OaBuildVersion",
    171u16 => "ClearCustData",
    172u16 => "VarInt",
    173u16 => "VarNeg",
    174u16 => "VarNot",
    175u16 => "VarRound",
    176u16 => "VarCmp",
    177u16 => "VarDecAdd",
    178u16 => "VarDecDiv",
    179u16 => "VarDecMul",
    180u16 => "CreateTypeLib2",
    181u16 => "VarDecSub",
    182u16 => "VarDecAbs",
    183u16 => "LoadTypeLibEx",
    184u16 => "SystemTimeToVariantTime",
    185u16 => "VariantTimeToSystemTime",
    186u16 => "UnRegisterTypeLib",
    187u16 => "VarDecFix",
    188u16 => "VarDecInt",
    189u16 => "VarDecNeg",
    190u16 => "VarDecFromUI1",
    191u16 => "VarDecFromI2",
    192u16 => "VarDecFromI4",
    193u16 => "VarDecFromR4",
    194u16 => "VarDecFromR8",
    195u16 => "VarDecFromDate",
    196u16 => "VarDecFromCy",
    197u16 => "VarDecFromStr",
    198u16 => "VarDecFromDisp",
    199u16 => "VarDecFromBool",
    200u16 => "GetErrorInfo",
    201u16 => "SetErrorInfo",
    202u16 => "CreateErrorInfo",
    203u16 => "VarDecRound",
    204u16 => "VarDecCmp",
    205u16 => "VarI2FromI1",
    206u16 => "VarI2FromUI2",
    207u16 => "VarI2FromUI4",
    208u16 => "VarI2FromDec",
    209u16 => "VarI4FromI1",
    210u16 => "VarI4FromUI2",
    211u16 => "VarI4FromUI4",
    212u16 => "VarI4FromDec",
    213u16 => "VarR4FromI1",
    214u16 => "VarR4FromUI2",
    215u16 => "VarR4FromUI4",
    216u16 => "VarR4FromDec",
    217u16 => "VarR8FromI1",
    218u16 => "VarR8FromUI2",
    219u16 => "VarR8FromUI4",
    220u16 => "VarR8FromDec",
    221u16 => "VarDateFromI1",
    222u16 => "VarDateFromUI2",
    223u16 => "VarDateFromUI4",
    224u16 => "VarDateFromDec",
    225u16 => "VarCyFromI1",
    226u16 => "VarCyFromUI2",
    227u16 => "VarCyFromUI4",
    228u16 => "VarCyFromDec",
    229u16 => "VarBstrFromI1",
    230u16 => "VarBstrFromUI2",
    231u16 => "VarBstrFromUI4",
    232u16 => "VarBstrFromDec",
    233u16 => "VarBoolFromI1",
    234u16 => "VarBoolFromUI2",
    235u16 => "VarBoolFromUI4",
    236u16 => "VarBoolFromDec",
    237u16 => "VarUI1FromI1",
    238u16 => "VarUI1FromUI2",
    239u16 => "VarUI1FromUI4",
    240u16 => "VarUI1FromDec",
    241u16 => "VarDecFromI1",
    242u16 => "VarDecFromUI2",
    243u16 => "VarDecFromUI4",
    244u16 => "VarI1FromUI1",
    245u16 => "VarI1FromI2",
    246u16 => "VarI1FromI4",
    247u16 => "VarI1FromR4",
    248u16 => "VarI1FromR8",
    249u16 => "VarI1FromDate",
    250u16 => "VarI1FromCy",
    251u16 => "VarI1FromStr",
    252u16 => "VarI1FromDisp",
    253u16 => "VarI1FromBool",
    254u16 => "VarI1FromUI2",
    255u16 => "VarI1FromUI4",
    256u16 => "VarI1FromDec",
    257u16 => "VarUI2FromUI1",
    258u16 => "VarUI2FromI2",
    259u16 => "VarUI2FromI4",
    260u16 => "VarUI2FromR4",
    261u16 => "VarUI2FromR8",
    262u16 => "VarUI2FromDate",
    263u16 => "VarUI2FromCy",
    264u16 => "VarUI2FromStr",
    265u16 => "VarUI2FromDisp",
    266u16 => "VarUI2FromBool",
    267u16 => "VarUI2FromI1",
    268u16 => "VarUI2FromUI4",
    269u16 => "VarUI2FromDec",
    270u16 => "VarUI4FromUI1",
    271u16 => "VarUI4FromI2",
    272u16 => "VarUI4FromI4",
    273u16 => "VarUI4FromR4",
    274u16 => "VarUI4FromR8",
    275u16 => "VarUI4FromDate",
    276u16 => "VarUI4FromCy",
    277u16 => "VarUI4FromStr",
    278u16 => "VarUI4FromDisp",
    279u16 => "VarUI4FromBool",
    280u16 => "VarUI4FromI1",
    281u16 => "VarUI4FromUI2",
    282u16 => "VarUI4FromDec",
    283u16 => "BSTR_UserSize",
    284u16 => "BSTR_UserMarshal",
    285u16 => "BSTR_UserUnmarshal",
    286u16 => "BSTR_UserFree",
    287u16 => "VARIANT_UserSize",
    288u16 => "VARIANT_UserMarshal",
    289u16 => "VARIANT_UserUnmarshal",
    290u16 => "VARIANT_UserFree",
    291u16 => "LPSAFEARRAY_UserSize",
    292u16 => "LPSAFEARRAY_UserMarshal",
    293u16 => "LPSAFEARRAY_UserUnmarshal",
    294u16 => "LPSAFEARRAY_UserFree",
    295u16 => "LPSAFEARRAY_Size",
    296u16 => "LPSAFEARRAY_Marshal",
    297u16 => "LPSAFEARRAY_Unmarshal",
    298u16 => "VarDecCmpR8",
    299u16 => "VarCyAdd",
    300u16 => "DllUnregisterServer",
    301u16 => "OACreateTypeLib2",
    303u16 => "VarCyMul",
    304u16 => "VarCyMulI4",
    305u16 => "VarCySub",
    306u16 => "VarCyAbs",
    307u16 => "VarCyFix",
    308u16 => "VarCyInt",
    309u16 => "VarCyNeg",
    310u16 => "VarCyRound",
    311u16 => "VarCyCmp",
    312u16 => "VarCyCmpR8",
    313u16 => "VarBstrCat",
    314u16 => "VarBstrCmp",
    315u16 => "VarR8Pow",
    316u16 => "VarR4CmpR8",
    317u16 => "VarR8Round",
    318u16 => "VarCat",
    319u16 => "VarDateFromUdateEx",
    322u16 => "GetRecordInfoFromGuids",
    323u16 => "GetRecordInfoFromTypeInfo",
    325u16 => "SetVarConversionLocaleSetting",
    326u16 => "GetVarConversionLocaleSetting",
    327u16 => "SetOaNoCache",
    329u16 => "VarCyMulI8",
    330u16 => "VarDateFromUdate",
    331u16 => "VarUdateFromDate",
    332u16 => "GetAltMonthNames",
    333u16 => "VarI8FromUI1",
    334u16 => "VarI8FromI2",
    335u16 => "VarI8FromR4",
    336u16 => "VarI8FromR8",
    337u16 => "VarI8FromCy",
    338u16 => "VarI8FromDate",
    339u16 => "VarI8FromStr",
    340u16 => "VarI8FromDisp",
    341u16 => "VarI8FromBool",
    342u16 => "VarI8FromI1",
    343u16 => "VarI8FromUI2",
    344u16 => "VarI8FromUI4",
    345u16 => "VarI8FromDec",
    346u16 => "VarI2FromI8",
    347u16 => "VarI2FromUI8",
    348u16 => "VarI4FromI8",
    349u16 => "VarI4FromUI8",
    360u16 => "VarR4FromI8",
    361u16 => "VarR4FromUI8",
    362u16 => "VarR8FromI8",
    363u16 => "VarR8FromUI8",
    364u16 => "VarDateFromI8",
    365u16 => "VarDateFromUI8",
    366u16 => "VarCyFromI8",
    367u16 => "VarCyFromUI8",
    368u16 => "VarBstrFromI8",
    369u16 => "VarBstrFromUI8",
    370u16 => "VarBoolFromI8",
    371u16 => "VarBoolFromUI8",
    372u16 => "VarUI1FromI8",
    373u16 => "VarUI1FromUI8",
    374u16 => "VarDecFromI8",
    375u16 => "VarDecFromUI8",
    376u16 => "VarI1FromI8",
    377u16 => "VarI1FromUI8",
    378u16 => "VarUI2FromI8",
    379u16 => "VarUI2FromUI8",
    401u16 => "OleLoadPictureEx",
    402u16 => "OleLoadPictureFileEx",
    411u16 => "SafeArrayCreateVector",
    412u16 => "SafeArrayCopyData",
    413u16 => "VectorFromBstr",
    414u16 => "BstrFromVector",
    415u16 => "OleIconToCursor",
    416u16 => "OleCreatePropertyFrameIndirect",
    417u16 => "OleCreatePropertyFrame",
    418u16 => "OleLoadPicture",
    419u16 => "OleCreatePictureIndirect",
    420u16 => "OleCreateFontIndirect",
    421u16 => "OleTranslateColor",
    422u16 => "OleLoadPictureFile",
    423u16 => "OleSavePictureFile",
    424u16 => "OleLoadPicturePath",
    425u16 => "VarUI4FromI8",
    426u16 => "VarUI4FromUI8",
    427u16 => "VarI8FromUI8",
    428u16 => "VarUI8FromI8",
    429u16 => "VarUI8FromUI1",
    430u16 => "VarUI8FromI2",
    431u16 => "VarUI8FromR4",
    432u16 => "VarUI8FromR8",
    433u16 => "VarUI8FromCy",
    434u16 => "VarUI8FromDate",
    435u16 => "VarUI8FromStr",
    436u16 => "VarUI8FromDisp",
    437u16 => "VarUI8FromBool",
    438u16 => "VarUI8FromI1",
    439u16 => "VarUI8FromUI2",
    440u16 => "VarUI8FromUI4",
    441u16 => "VarUI8FromDec",
    442u16 => "RegisterTypeLibForUser",
    443u16 => "UnRegisterTypeLibForUser",
 };

// Resource: https://docs.rs/exe/latest/src/exe/imphash.rs.html#6
pub static MAP_WS2_32_ORDINAL: phf::Map<u16, &'static str> = phf_map! {
    1u16 => "accept",
    2u16 => "bind",
    3u16 => "closesocket",
    4u16 => "connect",
    5u16 => "getpeername",
    6u16 => "getsockname",
    7u16 => "getsockopt",
    8u16 => "htonl",
    9u16 => "htons",
    10u16 => "ioctlsocket",
    11u16 => "inet_addr",
    12u16 => "inet_ntoa",
    13u16 => "listen",
    14u16 => "ntohl",
    15u16 => "ntohs",
    16u16 => "recv",
    17u16 => "recvfrom",
    18u16 => "select",
    19u16 => "send",
    20u16 => "sendto",
    21u16 => "setsockopt",
    22u16 => "shutdown",
    23u16 => "socket",
    24u16 => "GetAddrInfoW",
    25u16 => "GetNameInfoW",
    26u16 => "WSApSetPostRoutine",
    27u16 => "FreeAddrInfoW",
    28u16 => "WPUCompleteOverlappedRequest",
    29u16 => "WSAAccept",
    30u16 => "WSAAddressToStringA",
    31u16 => "WSAAddressToStringW",
    32u16 => "WSACloseEvent",
    33u16 => "WSAConnect",
    34u16 => "WSACreateEvent",
    35u16 => "WSADuplicateSocketA",
    36u16 => "WSADuplicateSocketW",
    37u16 => "WSAEnumNameSpaceProvidersA",
    38u16 => "WSAEnumNameSpaceProvidersW",
    39u16 => "WSAEnumNetworkEvents",
    40u16 => "WSAEnumProtocolsA",
    41u16 => "WSAEnumProtocolsW",
    42u16 => "WSAEventSelect",
    43u16 => "WSAGetOverlappedResult",
    44u16 => "WSAGetQOSByName",
    45u16 => "WSAGetServiceClassInfoA",
    46u16 => "WSAGetServiceClassInfoW",
    47u16 => "WSAGetServiceClassNameByClassIdA",
    48u16 => "WSAGetServiceClassNameByClassIdW",
    49u16 => "WSAHtonl",
    50u16 => "WSAHtons",
    51u16 => "gethostbyaddr",
    52u16 => "gethostbyname",
    53u16 => "getprotobyname",
    54u16 => "getprotobynumber",
    55u16 => "getservbyname",
    56u16 => "getservbyport",
    57u16 => "gethostname",
    58u16 => "WSAInstallServiceClassA",
    59u16 => "WSAInstallServiceClassW",
    60u16 => "WSAIoctl",
    61u16 => "WSAJoinLeaf",
    62u16 => "WSALookupServiceBeginA",
    63u16 => "WSALookupServiceBeginW",
    64u16 => "WSALookupServiceEnd",
    65u16 => "WSALookupServiceNextA",
    66u16 => "WSALookupServiceNextW",
    67u16 => "WSANSPIoctl",
    68u16 => "WSANtohl",
    69u16 => "WSANtohs",
    70u16 => "WSAProviderConfigChange",
    71u16 => "WSARecv",
    72u16 => "WSARecvDisconnect",
    73u16 => "WSARecvFrom",
    74u16 => "WSARemoveServiceClass",
    75u16 => "WSAResetEvent",
    76u16 => "WSASend",
    77u16 => "WSASendDisconnect",
    78u16 => "WSASendTo",
    79u16 => "WSASetEvent",
    80u16 => "WSASetServiceA",
    81u16 => "WSASetServiceW",
    82u16 => "WSASocketA",
    83u16 => "WSASocketW",
    84u16 => "WSAStringToAddressA",
    85u16 => "WSAStringToAddressW",
    86u16 => "WSAWaitForMultipleEvents",
    87u16 => "WSCDeinstallProvider",
    88u16 => "WSCEnableNSProvider",
    89u16 => "WSCEnumProtocols",
    90u16 => "WSCGetProviderPath",
    91u16 => "WSCInstallNameSpace",
    92u16 => "WSCInstallProvider",
    93u16 => "WSCUnInstallNameSpace",
    94u16 => "WSCUpdateProvider",
    95u16 => "WSCWriteNameSpaceOrder",
    96u16 => "WSCWriteProviderOrder",
    97u16 => "freeaddrinfo",
    98u16 => "getaddrinfo",
    99u16 => "getnameinfo",
    101u16 => "WSAAsyncSelect",
    102u16 => "WSAAsyncGetHostByAddr",
    103u16 => "WSAAsyncGetHostByName",
    104u16 => "WSAAsyncGetProtoByNumber",
    105u16 => "WSAAsyncGetProtoByName",
    106u16 => "WSAAsyncGetServByPort",
    107u16 => "WSAAsyncGetServByName",
    108u16 => "WSACancelAsyncRequest",
    109u16 => "WSASetBlockingHook",
    110u16 => "WSAUnhookBlockingHook",
    111u16 => "WSAGetLastError",
    112u16 => "WSASetLastError",
    113u16 => "WSACancelBlockingCall",
    114u16 => "WSAIsBlocking",
    115u16 => "WSAStartup",
    116u16 => "WSACleanup",
    151u16 => "__WSAFDIsSet",
    500u16 => "WEP",
};

// Resource: https://github.com/erocarrera/pefile/blob/master/ordlookup/wsock32.py
pub static MAP_WSOCK32_ORDINAL: phf::Map<u16, &'static str> = phf_map! {
    1u16 => "accept",
    2u16 => "bind",
    3u16 => "closesocket",
    4u16 => "connect",
    5u16 => "getpeername",
    6u16 => "getsockname",
    7u16 => "getsockopt",
    8u16 => "htonl",
    9u16 => "htons",
    10u16 => "inet_addr",
    11u16 => "inet_ntoa",
    12u16 => "ioctlsocket",
    13u16 => "listen",
    14u16 => "ntohl",
    15u16 => "ntohs",
    16u16 => "recv",
    17u16 => "recvfrom",
    18u16 => "select",
    19u16 => "send",
    20u16 => "sendto",
    21u16 => "setsockopt",
    22u16 => "shutdown",
    23u16 => "socket",
    24u16 => "MigrateWinsockConfiguration",
    51u16 => "gethostbyaddr",
    52u16 => "gethostbyname",
    53u16 => "getprotobyname",
    54u16 => "getprotobynumber",
    55u16 => "getservbyname",
    56u16 => "getservbyport",
    57u16 => "gethostname",
    101u16 => "WSAAsyncSelect",
    102u16 => "WSAAsyncGetHostByAddr",
    103u16 => "WSAAsyncGetHostByName",
    104u16 => "WSAAsyncGetProtoByNumber",
    105u16 => "WSAAsyncGetProtoByName",
    106u16 => "WSAAsyncGetServByPort",
    107u16 => "WSAAsyncGetServByName",
    108u16 => "WSACancelAsyncRequest",
    109u16 => "WSASetBlockingHook",
    110u16 => "WSAUnhookBlockingHook",
    111u16 => "WSAGetLastError",
    112u16 => "WSASetLastError",
    113u16 => "WSACancelBlockingCall",
    114u16 => "WSAIsBlocking",
    115u16 => "WSAStartup",
    116u16 => "WSACleanup",
    151u16 => "__WSAFDIsSet",
    500u16 => "WEP",
    1000u16 => "WSApSetPostRoutine",
    1100u16 => "inet_network",
    1101u16 => "getnetbyname",
    1102u16 => "rcmd",
    1103u16 => "rexec",
    1104u16 => "rresvport",
    1105u16 => "sethostname",
    1106u16 => "dn_expand",
    1107u16 => "WSARecvEx",
    1108u16 => "s_perror",
    1109u16 => "GetAddressByNameA",
    1110u16 => "GetAddressByNameW",
    1111u16 => "EnumProtocolsA",
    1112u16 => "EnumProtocolsW",
    1113u16 => "GetTypeByNameA",
    1114u16 => "GetTypeByNameW",
    1115u16 => "GetNameByTypeA",
    1116u16 => "GetNameByTypeW",
    1117u16 => "SetServiceA",
    1118u16 => "SetServiceW",
    1119u16 => "GetServiceA",
    1120u16 => "GetServiceW",
    1130u16 => "NPLoadNameSpaces",
    1140u16 => "TransmitFile",
    1141u16 => "AcceptEx",
    1142u16 => "GetAcceptExSockaddrs",
};

// This is used for resolving debug type in the `display_pe_debug` function.
pub static MAP_DEBUG_TYPE: phf::Map<u32, &'static str> = phf_map! {
    0u32 => "???",
    1u32 => "COFF",
    2u32 => "CodeView",
    3u32 => "FPO",
    4u32 => "Misc",
    5u32 => "Exception",
    6u32 => "Fixup",
    7u32 => "OMAP-to-SRC",
    8u32 => "OMAP-from-SRC",
    // 9u32 => "Reserved for Borland",
    // 10u32 => "Reserved",
    // 11u32 => "Reserved",
    16u32 => "REPRO",
    17u32 => "Undefined",
    19u32 => "Undefined",
    20u32 => "Extended DLL Characteristics",
};