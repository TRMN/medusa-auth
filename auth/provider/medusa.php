<?php

namespace TRMN\medusaauth\auth\provider;


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
     * @param       \phpbb\db\driver\driver_interface               $db             Database object
     * @param       \phpbb\config\config            $config         Config object
     * @param       \phpbb\passwords\manager        $passwords_manager              Passwords manager object
     * @param       \phpbb\user                     $user           User object
     */
    public function __construct(\phpbb\db\driver\driver_interface $db, \phpbb\config\config $config, \phpbb\passwords\manager $passwords_manager, \phpbb\user $user)
    {
        $this->db = $db;
        $this->config = $config;
        $this->passwords_manager = $passwords_manager;
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function login($username, $password)
    {
        // Auth plugins get the password untrimmed.
        // For compatibility we trim() here.
        $password = trim($password);

        // do not allow empty password
        if (!$password)
        {
            return array(
                'status'    => LOGIN_ERROR_PASSWORD,
                'error_msg' => 'NO_PASSWORD_SUPPLIED',
                'user_row'  => array('user_id' => ANONYMOUS),
            );
        }

        if (!$username)
        {
            return array(
                'status'    => LOGIN_ERROR_USERNAME,
                'error_msg' => 'LOGIN_ERROR_USERNAME',
                'user_row'  => array('user_id' => ANONYMOUS),
            );
        }

        $ch = curl_init('https://medusa.trmn.org/oauth/token');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS,'username=' . $username . '&password=' . $password . '&grant_type=password&client_id=medusamobile');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_exec($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpcode == "200") {
            // Good login, check to see if we have a profile

            $sql = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type
                                        FROM ' . USERS_TABLE . "
                                        WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($username)) . "'";
            $result = $this->db->sql_query($sql);
            $row = $this->db->sql_fetchrow($result);
            $this->db->sql_freeresult($result);

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

                // generate user account data
                $medusa_user_row = array(
                    'username' => $username,
                    'user_password' => $this->passwords_manager->hash($password),
                    'user_email' => $username,
                    'group_id' => (int)$row['group_id'],
                    'user_type' => USER_NORMAL,
                    'user_ip' => $this->user->ip,
                    'user_new' => ($this->config['new_member_post_limit']) ? 1 : 0,
                );

                // this is the user's first login so create an empty profile
                return array(
                    'status' => LOGIN_SUCCESS_CREATE_PROFILE,
                    'error_msg' => false,
                    'user_row' => $medusa_user_row,
                );
            }
        }
    }
}