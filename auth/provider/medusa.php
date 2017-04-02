<?php

namespace TRMN\medusaauth\auth\provider;

use \phpbb\language\language;

class medusa extends \phpbb\auth\provider\base
{
    /**
     * phpBB passwords manager
     *
     * @var \phpbb\passwords\manager
     */
    protected $passwords_manager;

    /**
     * MEDUSA Authentication Constructor
     *
     * @param       \phpbb\db\driver\driver_interface $db                Database object
     * @param       \phpbb\config\config              $config            Config object
     * @param       \phpbb\passwords\manager          $passwords_manager Passwords manager object
     * @param       \phpbb\user                       $user              User object
     */
    public function __construct(
        \phpbb\db\driver\driver_interface $db,
        \phpbb\config\config $config,
        \phpbb\passwords\manager $passwords_manager,
        \phpbb\user $user,
        \phpbb\language\language_file_loader $loader
    ) {
        $this->db = $db;
        $this->config = $config;
        $this->passwords_manager = $passwords_manager;
        $this->user = $user;

        // Load our language file
        $language = new language($loader);
        $language->add_lang('common', 'TRMN/medusaauth');
    }

    /**
     * {@inheritdoc}
     */
    public function login($username, $password)
    {
        global $phpbb_root_path, $phpEx;

        // Auth plugins get the password untrimmed.
        // For compatibility we trim() here.
        $password = trim($password);

        // do not allow empty password
        if (!$password) {
            return array(
                'status' => LOGIN_ERROR_PASSWORD,
                'error_msg' => 'NO_PASSWORD_SUPPLIED',
                'user_row' => array('user_id' => ANONYMOUS),
            );
        }

        if (!$username) {
            return array(
                'status' => LOGIN_ERROR_USERNAME,
                'error_msg' => 'LOGIN_ERROR_USERNAME',
                'user_row' => array('user_id' => ANONYMOUS),
            );
        }

        $username = strtolower($username);
        $ch = curl_init('https://medusa.trmn.org/oauth/token');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS,
            'username=' . $username . '&password=' . $password . '&grant_type=password&client_id=medusamobile');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $results = json_decode(curl_exec($ch));
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpcode == "200") {
            // Good login, check to see if we have a profile

            $row = $this->_userExists($username);

            if ($row) {
                // User inactive...
                if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) {
                    return array(
                        'status' => LOGIN_ERROR_ACTIVE,
                        'error_msg' => 'ACTIVE_ERROR',
                        'user_row' => $row,
                    );
                }

                // Successful login... set user_login_attempts to zero...

                $medusa_user = $this->_getUserInfo($results->access_token);

                $forum_rank = $this->_lookUpRank($medusa_user->rank->grade, $medusa_user->branch);

                if (!is_null($forum_rank)) {
                    $row['user_rank'] = $forum_rank;
                }

                return array(
                    'status' => LOGIN_SUCCESS,
                    'error_msg' => false,
                    'user_row' => $row,
                );
            } else {
                // Good login, no profile exists

                // retrieve default group id
                $sql = 'SELECT group_id
                                                FROM ' . GROUPS_TABLE . "
                                                WHERE group_name = '" . $this->db->sql_escape('REGISTERED') . "'
                                                        AND group_type = " . GROUP_SPECIAL;
                $result = $this->db->sql_query($sql);
                $row = $this->db->sql_fetchrow($result);
                $this->db->sql_freeresult($result);

                if (!$row) {
                    trigger_error('NO_GROUP');
                }

                $medusa_user = $this->_getUserInfo($results->access_token);
                
                if (is_null($medusa_user)) {
                    return [
                        'status' => LOGIN_ERROR_EXTERNAL_AUTH,
                        'error_msg' => 'MEDUSA_NO_USER_INFO',
                        'user_row' => ['user_id' => ANONYMOUS],
                    ];
                }

                // generate user account data
                $medusa_user_row = [
                    'username' => $medusa_user->first_name . ' ' . $medusa_user->last_name,
                    'username_clean' => $this->db->sql_escape(utf8_clean_string($medusa_user->first_name . ' ' . $medusa_user->last_name)),
                    'user_password' => $this->passwords_manager->hash($password),
                    'user_email' => $username,
                    'group_id' => (int)$row['group_id'],
                    'user_type' => USER_NORMAL,
                    'user_ip' => $this->user->ip,
                    'user_new' => 0,
                ];

                $forum_rank = $this->_lookUpRank($medusa_user->rank->grade, $medusa_user->branch);

                if (!is_null($forum_rank)) {
                    $medusa_user_row['user_rank'] = $forum_rank;
                }

                // we are going to use the user_add function so include functions_user.php if it wasn't defined yet
                if (!function_exists('user_add')) {
                    include($phpbb_root_path . 'includes/functions_user.' . $phpEx);
                }

                user_add($medusa_user_row, ['pf_membernumber' => $results->member_id]);

                $row = $this->_userExists($username);

                if (!row) {
                    return [
                        'status' => LOGIN_ERROR_EXTERNAL_AUTH,
                        'error_msg' => 'AUTH_NO_PROFILE_CREATED',
                        'user_row' => ['user_id' => ANONYMOUS],
                    ];
                }

                // this is the user's first login so create an empty profile
                return [
                    'status' => LOGIN_SUCCESS,
                    'error_msg' => false,
                    'user_row' => $row,
                ];
            }
        }
    }

    private function _lookUpRank($rank, $branch)
    {
        $grades = json_decode('{"E-1":{"RMN":"Spacer 3rd Class","RMMC":"Private","RMA":"Private","GSN":"Spacer 3rd Class","RHN":"Spacer 3rd Class","IAN":"Gefraiter"},"E-2":{"RMN":"Spacer 2nd Class","RMMC":"Private First Class","RMA":"Private First Class","GSN":"Spacer 2nd Class","RHN":"Spacer 2nd Class","IAN":"Obergefraiter"},"E-3":{"RMN":"Spacer 1st Class","RMMC":"Lance Corporal","RMA":"Lance Corporal","GSN":"Spacer 1st Class","RHN":"Spacer 1st Class","IAN":"Hauptgefraiter"},"E-4":{"RMN":"Petty Officer 3rd Class","RMMC":"Corporal","RMA":"Corporal","GSN":"Petty Officer 3rd Class","RHN":"Petty Officer 3rd Class","IAN":"Maat"},"E-5":{"RMN":"Petty Officer 2nd Class","RMMC":"Platoon Sergeant","RMA":"Platoon Sergeant","GSN":"Petty Officer 2nd Class","RHN":"Petty Officer 2nd Class","IAN":"Obermaat"},"E-6":{"RMN":"Petty Officer 1st Class","RMMC":"Staff Sergeant","RMA":"Staff Sergeant","GSN":"Petty Officer 1st Class","RHN":"Petty Officer 1st Class","IAN":"Bootsman"},"E-7":{"RMN":"Chief Petty Officer","RMMC":"Master Sergeant","RMA":"Master Sergeant","GSN":"Chief Petty Officer","RHN":"Chief Petty Officer","IAN":"Oberbootsman"},"E-8":{"RMN":"Senior Chief Petty Officer","RMMC":"First Sergeant","RMA":"First Sergeant","GSN":"Senior Chief Petty Officer","RHN":"Senior Chief Petty Officer","IAN":"Stabsbootsman"},"E-9":{"RMN":"Master Chief Petty Officer","RMMC":"Sergeant Major","RMA":"Sergeant Major","GSN":"Master Chief Petty Officer","RHN":"Master Chief Petty Officer","IAN":"Oberstabsbootsman"},"E-10":{"RMN":"Senior Master Chief Petty Officer","RMMC":"Regimental Sergeant Major","RMA":"Regimental Sergeant Major","GSN":"Senior Master Chief Petty Officer","RHN":"Master Chief Petty Officer of the Navy","IAN":"Oberstabsbootsman der Flotte"},"WO-1":{"RMN":"Warrant Officer","RMMC":"Warrant Officer","RMA":"Warrant Officer 1st Class","GSN":"Warrant Officer"},"WO-2":{"RMN":"Warrant Officer 1st Class","RMMC":"Warrant Officer 1st Class","RMA":"Warrant Officer 2nd Class","GSN":"Chief Warrant Officer"},"WO-3":{"RMN":"Chief Warrant Officer","RMMC":"Chief Warrant Officer","RMA":"Chief Warrant Officer","GSN":"Senior Chief Warrant Officer"},"WO-4":{"RMN":"Senior Chief Warrant Officer","RMMC":"Senior Chief Warrant Officer","RMA":"Senior Chief Warrant Officer","GSN":"Master Chief Warrant Officer"},"WO-5":{"RMN":"Master Chief Warrant Officer","RMMC":"Master Chief Warrant Officer","RMA":"Master Chief Warrant Officer","GSN":"Senior Master Chief Warrant Officer"},"MID":{"RMA":"","RMMC":"","RMN":"Midshipman","GSN":"Midshipman","IAN":"","RHN":""},"O-1":{"RMN":"Ensign","RMMC":"2nd Lieutenant","RMA":"2nd Lieutenant","GSN":"Ensign","RHN":"Ensign","IAN":"Leutnant der Sterne"},"O-2":{"RMN":"Lieutenant (JG)","RMMC":"1st Lieutenant","RMA":"1st Lieutenant","GSN":"Lieutenant (JG)","RHN":"Lieutenant (JG)","IAN":"Oberleutnant der Sterne"},"O-3":{"RMN":"Lieutenant (SG)","RMMC":"Captain","RMA":"Captain","GSN":"Lieutenant (SG)","RHN":"Lieutenant (SG)","IAN":"Kapitainleutnant"},"O-4":{"RMN":"Lieutenant Commander","RMMC":"Major","RMA":"Major","GSN":"Lieutenant Commander","RHN":"Lieutenant Commander","IAN":"Korvettenkapitain"},"O-5":{"RMN":"Commander","RMMC":"Lieutenant Colonel","RMA":"Lieutenant Colonel","GSN":"Commander","RHN":"Commander","IAN":"Fregattenkapitain"},"O-6":{"RMN":"","RMMC":"Colonel","RMA":"Colonel","GSN":"Captain","RHN":"Captain","IAN":"Kapitain der Sterne"},"O-6-A":{"RMN":"Captain (JG)","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"O-6-B":{"RMN":"Captain (SG)","RMMC":"","RMA":"","GSN":"Captain","RHN":"Captain","IAN":"Kapitain der Sterne"},"F-1":{"RMN":"Commodore","RMMC":"Brigadier General","RMA":"Brigadier General","GSN":"Commodore","RHN":"Commodore","IAN":"Flotillenadmiral"},"F-2":{"RMN":"","RMMC":"Major General","RMA":"Major General","GSN":"Rear Admiral","RHN":"Rear Admiral","IAN":"Konteradmiral"},"F-2-A":{"RMN":"Rear Admiral of the Red","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-2-B":{"RMN":"Rear Admiral of the Green","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-3":{"RMN":"","RMMC":"Lieutenant General","RMA":"Lieutenant General","GSN":"Vice Admiral","RHN":"Vice Admiral","IAN":"Vizeadmiral"},"F-3-A":{"RMN":"Vice Admiral of the Red","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-3-B":{"RMN":"Vice Admiral of the Green","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-4":{"RMN":"","RMMC":"General","RMA":"General","GSN":"Admiral","RHN":"Admiral","IAN":"Admiral"},"F-4-A":{"RMN":"Admiral of the Red","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-4-B":{"RMN":"Admiral of the Green","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-5":{"RMN":"","RMMC":"Field Marshal","RMA":"Field Marshal","GSN":"Fleet Admiral"},"F-5-A":{"RMN":"Fleet Admiral of the Red","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-5-B":{"RMN":"Fleet Admiral of the Green","RMMC":"","RMA":"","GSN":"","RHN":"","IAN":""},"F-6":{"RMN":"Admiral of the Fleet","RMMC":"Marshal of the Corps","RMA":"Marshal of the Army","GSN":"High Admiral"},"E-11":{"RMA":"Command Sergeant Major"},"E-12":{"RMA":"Sergeant Major of the Army"}}', true);

        $rank = trim(str_replace([' of the Red', ' of the Green'], '', $grades[$rank][$branch]));

        $sql = 'SELECT rank_id FROM ' . RANKS_TABLE . " WHERE rank_title = '";

        // Check for more specific 'Rank - Branch' first

        $result = $this->db->sql_query($sql . $rank . ' - ' . $branch . "'");
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);

        if (!$row) {
            $result = $this->db->sql_query($sql . $rank . "'");
            $row = $this->db->sql_fetchrow($result);
            $this->db->sql_freeresult($result);

            if (!$row) {
                return null;
            }

            return $row['rank_id'];
        }
    }

    private function _userExists($username)
    {
        $sql = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type
                                        FROM ' . USERS_TABLE . "
                                        WHERE user_email = '" . $username . "'";
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);

        return $row;
    }
    
    private function _getUserInfo($token)
    {
        // Get user info from MEDUSA

        $url = 'https://medusa.trmn.org/oauth/user';
        $headers = [];

        if (strlen($token) < 100) {
            $url .= '?access_token=' . $token;
        } else {
            $headers[] = 'Authorization: Bearer ' . $token;
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if (count($headers) > 0) {
            curl_setopt($ch, CURLOPT_HEADER, $headers);
        }

        $results = json_decode(curl_exec($ch));
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpcode == 200) {
            return $results;
        }
        
        return null;
    }
}