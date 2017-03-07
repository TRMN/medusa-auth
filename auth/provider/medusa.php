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

                // Get user info from MEDUSA

                $url = 'https://medusa.trmn.org/oauth/user';
                $headers = [];

                if (strlen($results->access_token) < 100) {
                    $url .= '?access_token=' . $results->access_token;
                } else {
                    $headers[] = 'Authorization: Bearer ' . $results->access_token;
                }

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

                if (count($headers) > 0) {
                    curl_setopt($ch, CURLOPT_HEADER, $headers);
                }

                $results = json_decode(curl_exec($ch));
                $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);

                if ($httpcode != '200') {
                    return [
                        'status' => LOGIN_ERROR_EXTERNAL_AUTH,
                        'error_msg' => 'MEDUSA_NO_USER_INFO',
                        'user_row' => ['user_id' => ANONYMOUS],
                    ];
                }

                // generate user account data
                $medusa_user_row = [
                    'username' => $results->member_id,
                    'username_clean' => $this->db->sql_escape(utf8_clean_string($results->member_id)),
                    'user_password' => $this->passwords_manager->hash($password),
                    'user_email' => $username,
                    'group_id' => (int)$row['group_id'],
                    'user_type' => USER_NORMAL,
                    'user_ip' => $this->user->ip,
                    'user_new' => 0,
                ];

                $forum_rank = $this->_lookUpRank($results->rank_title, $results->branch);

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
        $rank = str_replace([' of the Red', ' of the Green'], '', $rank);

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
}