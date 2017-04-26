#ifndef _SIDER_PATTERNS_H
#define _SIDER_PATTERNS_H


// livecpk patterns
static BYTE lcpk_pattern_get_buffer_size[16] = 
    "\x8b\x8d\xc0\xff\xff\xff"
    "\x8b\x85\xbc\xff\xff\xff"
    "\x83\xc4\x0c";
static BYTE lcpk_pattern_create_buffer[15] =
    "\x89\x46\x38"
    "\x39\x5e\x38"
    "\x0f\x84\xee\x00\x00\x00"
    "\x6a\x01";
static BYTE lcpk_pattern_after_read[18] =
    "\xc7\x46\x10\x01\x00\x00\x00"
    "\x83\x7e\x10\x01"
    "\x0f\x85\xbb\x00\x00\x00";
static BYTE lcpk_pattern_lookup_file[17] =
    "\xeb\x6c"
    "\x8d\x85\xac\xfd\xff\xff"
    "\x50"
    "\x8d\x85\xb0\xfd\xff\xff"
    "\x50";
static int lcpk_offs_lookup_file = -5;

static BYTE lcpk_pattern_get_file_info[12] = 
    "\x83\x67\x14\x00"
    "\x83\x67\x1c\x00"
    "\x89\x4f\x04";

static BYTE lcpk_pattern_before_read[10] =
    "\x89\x46\x18"
    "\xc6\x46\x6c\x01"
    "\x31\xc0";
static int lcpk_offs_before_read = -12;

static BYTE lcpk_pattern_at_read_file[14] =
    "\x56"
    "\x8d\x45\x08"
    "\x50"
    "\x53"
    "\xff\x75\x1c"
    "\xff\x37"
    "\xff\x15";
static int lcpk_offs_at_read_file = 11;

static BYTE lcpk_pattern_at_set_file_pointer[23] =
    "\xff\x75\x14"
    "\x89\x85\xfc\xff\xff\xff"
    "\x8d\x85\xfc\xff\xff\xff"
    "\x50"
    "\xff\x75\x0c"
    "\xff\x75\x08";
static int lcpk_offs_at_set_file_pointer = 22;

// more patterns
static BYTE bb_pattern[13] =
    "\x80\x7e\x0c\x00"
    "\x75\x06"
    "\x80\x7e\x0d\x00"
    "\x74\x09";
static int bb_offs = 4;

static BYTE trophy_pattern[11] =
    "\x56"
    "\x89\xce"
    "\x50"
    "\x89\x86\x08\x2c\x00\x00";
static int trophy_offs = 4;

// team ids
static BYTE team_ids_pattern1[14] =
    "\x81\xe2\xff\x3f\x00\x00"
    "\x31\x94\xb5\xc8\xff\xff\xff";
static int team_ids_off1 = 0x38;

static BYTE team_ids_pattern2[18] =
    "\x81\xc7\x48\x02\x00\x00"
    "\xb9\x0b\x00\x00\x00"
    "\x8d\xb5\xa0\xff\xff\xff";
static int team_ids_off2 = 0x22;

/*
static BYTE team_ids_pattern2[] =
    "\x66\x89\x86\xf8\x01\x00\x00"
    "\x89\x8e\xfc\x01\x00\x00"
    "\x66\x89\x53\x2c";
static int team_ids_off2 = -8;
*/

// number of minutes
static BYTE minutes_pattern[14] =
    "\x55"
    "\x89\xe5"
    "\x8a\x45\x08"
    "\x88\x41\x14"
    "\x5d"
    "\xc2\x04\x00";
static int minutes_off = 3;

// time clamp pattern
static BYTE time_clamp_pattern[17] =
    "\xdb\x45\x08"
    "\xd9\x5d\x08"
    "\xd9\x45\x08"
    "\xd9\x56\x54"
    "\xd9\xe8"
    "\xd8\xd1";
static BYTE time_clamp_off = 0x36;

// set default settings
static BYTE settings_pattern[16] =
    "\xc7\x06\xff\xff\xff\xff"
    "\xc7\x46\x08\x37\x00\x00\x00"
    "\x88\x5e";
static int settings_off = 0;

// write tournament id
static BYTE write_tid_pattern[18] =
    "\x8b\x7d\x08"
    "\x66\x8b\x07"
    "\x66\x89\x06"
    "\x66\x8b\x4f\x02"
    "\x66\x89\x4e\x02";
static int write_tid_off = 17;

// write exhib id
static BYTE write_exhib_id_pattern[14] =
    "\xc7\x46\x50\x02\x00\x00\x00"
    "\x5e"
    "\xc3"
    "\x8b\x46\x4c"
    "\x50";
static int write_exhib_id_off = 0x22;

// tid function pattern
static BYTE tid_func_pattern[12] =
    "\x83\xc0\xda"
    "\x83\xc4\x04"
    "\x83\xf8\x3f"
    "\x77\x14";
static int tid_func_off1 = -5;
static int tid_func_off2 = -0x1c;

// write stadium settings pattern
static BYTE write_stadium_pattern[18] =
    "\x8d\x8d\xb0\xfd\xff\xff"
    "\x51"
    "\xc7\x85\xfc\xff\xff\xff\xff\xff\xff\xff";
static int write_stadium_off = 0;

// read ball name pattern
static BYTE read_ball_name_pattern[26] =
    "\x30\xc0"
    "\x5d"
    "\xc2\x08\x00"
    "\x8d\x51\x08"
    "\x89\xd0"
    "\x56"
    "\x8d\x70\x01"
    "\x8a\x08"
    "\x40"
    "\x84\xc9"
    "\x75\xf9"
    "\x8b\x4d\x0c";
static int read_ball_name_off = 6;

// read stadium name pattern
static BYTE read_stad_name_pattern[26] =
    "\x30\xc0"
    "\x5d"
    "\xc2\x08\x00"
    "\x8d\x51\x0c"
    "\x89\xd0"
    "\x56"
    "\x8d\x70\x01"
    "\x8a\x08"
    "\x40"
    "\x84\xc9"
    "\x75\xf9"
    "\x8b\x4d\x0c";
static int read_stad_name_off = 6;

// read empty stad name pattern
static BYTE read_no_stad_name_pattern[21] =
    "\x0f\xb6\x88\x16\x03\x00\x00"
    "\x39\xcb"
    "\x75\x24"
    "\x8d\x50\x50"
    "\x89\xd0"
    "\x57"
    "\x8d\x78\x01";
static int read_no_stad_name_off = 0x4f;

// edit mode pattern
static BYTE edit_mode_pattern[25] =
    "\x56"
    "\x89\xce"
    "\x8b\x86\xc8\x00\x00\x00"
    "\x83\xe8\x00"
    "\x74\x46"
    "\x83\xe8\x02"
    "\x74\x2c"
    "\x83\xe8\x02"
    "\x75\x59";
static int enter_edit_mode_off = 0x67;
static int exit_edit_mode_off = 0x44;

// gameplay: ball physics
static BYTE ball_physics_pattern[23] =
    "\xd9\x5d\x14"
    "\xd9\x45\x14"
    "\xdd\x85\xf4\xff\xff\xff"
    "\xd8\xc8"
    "\xd9\x5d\x14"
    "\xd9\x56\x14"
    "\xdc\x0d";
static int ball_physics_off = 22;

// gameplay: ball weight
static BYTE ball_weight_pattern[22] = 
    "\xdf\xe0"
    "\xf6\xc4\x05"
    "\x7a\xcc"
    "\xdd\x86\xe8\x01\x00\x00"
    "\x8d\x95\xf0\xff\xff\xff"
    "\xdc\x0d";
static int ball_weight_off = 21;
static int ball_bounce_off = 27;

// gameplay: speed global
static BYTE speed_global_pattern[24] =
    "\xd9\x85\xcf\xff\xff\xff"
    "\xd8\xd9"
    "\xdf\xe0"
    "\xf6\xc4\x05"
    "\x7b\x46"
    "\x8b\x95\xe4\xff\xff\xff"
    "\xdc\x25";
static int speed_global_off = 23;

// gameplay: speed
static BYTE speed_pattern[20] =
    "\xdc\x9d\x94\xff\xff\xff"
    "\xdf\xe0"
    "\xf6\xc4\x06"
    "\x0f\x8a\x21\x03\x00\x00"
    "\xd9\xee";
static int speed_pattern_off = -4;

// gameplay: shooting power
static BYTE shot_power_pattern[12] =
    "\xd9\x9d\xd0\xff\xff\xff"
    "\xd9\x40\x04"
    "\xdc\x0d";
static int shot_power_off = 11;

#endif

