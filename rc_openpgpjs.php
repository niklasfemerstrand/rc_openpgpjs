<?php
/*
+-------------------------------------------------------------------------+
| OpenPGP.js implemented in Roundcube                                     |
|                                                                         |
| Copyright (C) 2013 Niklas Femerstrand <nik@qnrq.se>                     |
|                                                                         |
| This program is free software; you can redistribute it and/or modify    |
| it under the terms of the GNU General Public License version 2          |
| as published by the Free Software Foundation.                           |
|                                                                         |
| This program is distributed in the hope that it will be useful,         |
| but WITHOUT ANY WARRANTY; without even the implied warranty of          |
| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
| GNU General Public License for more details.                            |
|                                                                         |
| You should have received a copy of the GNU General Public License along |
| with this program; if not, write to the Free Software Foundation, Inc., |
| 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             |
|                                                                         |
+-------------------------------------------------------------------------+
*/

class rc_openpgpjs extends rcube_plugin {
  public $task = 'mail|settings';
  public $rc;

  /**
   * Plugin initialization.
   */
  function init() {
    $this->version_detect();

    $this->rc = rcube::get_instance();
    $this->rm = rcmail::get_instance();

    $this->add_hook('user_create', array($this, 'user_create'));
    $this->register_action('plugin.pks_search', array($this, 'hkp_search'));
    $this->register_action('plugin.hkp_add', array($this, 'hkp_add'));
    $this->register_action('plugin.pubkey_save', array($this, 'pubkey_save'));

    if ($this->rc->task == 'mail') {
      $this->add_hook('render_page', array($this, 'render_page'));

      // make localization available on the client
      $this->add_texts('localization/', true);

      // load js
      $this->include_script('js/openpgp.min.js');
      $this->include_script('js/rc_openpgpjs.crypto.js');
      $this->include_script('js/rc_openpgpjs.js');

      if(isset($_SESSION["rc_openpgpjs_outdated"])) {
        $this->include_script('js/outdated.js');
      }

      // load css
      $this->include_stylesheet($this->local_skin_path() . '/rc_openpgpjs.css');

      // add public key attachment related hooks
      $this->add_hook('message_compose', array($this, 'message_compose'));
      $this->add_hook('message_sent', array($this, 'unlink_pubkey'));

      if ($this->api->output->type == 'html') {
        // add key manager item to message menu
        $opts = array("command"    => "open-key-manager",
                      "label"      => "rc_openpgpjs.key_manager",
                      "type"       => "link",
                      "classact"   => "icon active",
                      "class"      => "icon",
                      "innerclass" => "icon key_manager");
        $this->api->add_content(html::tag('li', null, $this->api->output->button($opts)), "messagemenu");

        if ($this->rc->action == 'compose') {

            if ( $this->is_enabled()) 
            {
               // Add hidden field to determine if warning should be enabled
               $openpgp_warn_opts = array('id' => 'openpgpjs_warn',
                   'type' => 'hidden',
                   'value' => $this->rc->config->get('warn_on_unencrypted', false)?'1':'0'
               );
               $opengpg_warn = new html_inputfield($openpgp_warn_opts);
               $this->api->add_content( html::span('composeoption', html::label(null, $opengpg_warn->show())), "composeoptions");

              // add key manager button to compose toolbar
              $opts = array("command"    => "open-key-manager",
                            "label"      => "rc_openpgpjs.key_manager",
                            "type"       => "link",
                            "classact"   => "button active key_manager",
                            "class"      => "button key_manager");
              $this->api->add_content($this->api->output->button($opts), "toolbar");
              
              // add encrypt and sign checkboxes to composeoptions
              $encrypt_opts = array('id' => 'openpgpjs_encrypt',
                                    'type' => 'checkbox');
              if($this->rc->config->get('encrypt', false)) {
                 $encrypt_opts['checked'] = 'checked';
              }
              $encrypt = new html_inputfield($encrypt_opts);
              $this->api->add_content(
                html::span('composeoption', html::label(null, $encrypt->show() . $this->gettext('encrypt'))),
                "composeoptions"
              );
              $sign_opts = array('id' => 'openpgpjs_sign',
                                 'type' => 'checkbox');
              if($this->rc->config->get('sign', false)) {
                 $sign_opts['checked'] = 'checked';
              }
              $sign = new html_inputfield($sign_opts);
              $this->api->add_content(
                html::span('composeoption', html::label(null, $sign->show() . $this->gettext('sign'))),
                "composeoptions"
              );
            }
        }
      }
    } elseif ($this->rc->task == 'settings') {
      // load localization
      $this->add_texts('localization/', false);

      // load style sheet
      $this->include_stylesheet($this->local_skin_path() . '/rc_openpgpjs.css');
      
      // add hooks for OpenPGP settings
      $this->add_hook('preferences_sections_list', array($this, 'preferences_sections_list'));
      $this->add_hook('preferences_list', array($this, 'preferences_list'));
      $this->add_hook('preferences_save', array($this, 'preferences_save'));
    } 
  }

  // Match remote version string with local version string to detect outdated plugin installs
  private function version_detect() {
    /**
     * TODO: Setup listening httpd somewhere to serve latest file. Requires some infrastructure, like a website for the proj. This is TEMP.
     */
    if(!isset($_SESSION["rc_openpgpjs_ver"]) || $_SESSION["rc_openpgpjs_ver"] < date("Ymd")) {
      $local_src = file_get_contents(__DIR__."/js/rc_openpgpjs.js");
      if(ini_get("allow_url_fopen") === "1") {
        $remote_src = file_get_contents("https://raw.github.com/qnrq/rc_openpgpjs/master/js/rc_openpgpjs.js");
      } elseif(ini_get("allow_url_fopen") != "1") {
        if(!function_exists("curl_init")) {
          // TODO: Add failure notif msg
          return false;
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://raw.github.com/qnrq/rc_openpgpjs/master/js/rc_openpgpjs.js");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $remote_src = curl_exec($ch);

        if(curl_errno($ch)) {
          // TODO: Add failure notif msg
          return false;
        }

        curl_close($ch);
      }

      preg_match("/var VERSTR = \"(.*)\"/", $remote_src, $remoteM);
      preg_match("/var VERSTR = \"(.*)\"/", $local_src, $localM);

      if(isset($remoteM[1]) && isset($localM[1])) {
        if($remoteM[1] != $localM[1]) {
          $_SESSION["rc_openpgpjs_outdated"] = 1;
        }
      }

      $_SESSION["rc_openpgpjs_ver"] = date("Ymd"); // Checking once a day per session should be fine
    }
  }

  private function is_enabled()
  {
    return $this->rc->config->get('openpgp_enabled', 0);
  }

  /**
   * Add key manager and key selector to html output
   *
   * @param array Original parameters
   * @return array Modified parameters
   */
  function render_page($params) {
    $template_path = $this->home . '/'. $this->local_skin_path();
    $this->rc->output->add_footer($this->rc->output->just_parse(
      file_get_contents($template_path . '/templates/key_manager.html') .
      file_get_contents($template_path . '/templates/key_search.html') .
      file_get_contents($template_path . '/templates/key_select.html')));
    $this->rc->output->add_footer(html::div(array('style' => "visibility: hidden;",
                                                  'id' => "openpgpjs_identities"),
                                  json_encode($this->rm->user->list_identities())));

    return $params;
  }

  /**
   * Create default identity, required as pubkey metadata
   */
  function user_create($params) {
    $params['user_name'] = preg_replace("/@.*$/", "", $params['user']);
    $params['user_email'] = $params['user'];
    return $params;
  }

  /**
   * This Public Key Server proxy is written to circumvent Access-Control-Allow-Origin
   * limitations. It also provides a layer of security as HKP normally doesn't
   * support HTTPS; essentially preventing MITM if the Roundcube installation
   * is configured to use HTTPS.
   *
   * For more details see the following:
   *   http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
   *   http://sks-keyservers.net/
   *
   *    Please use http://pool.sks-keyservers.net as the source for this proxy
   */
  function hkp_search() {
    if(!isset($_POST['op']) || !isset($_POST['search'])) {
      return $this->rc->output->command(
        'plugin.pks_search',
        array('message' => "ERR: Missing param",
              'op' => htmlspecialchars($_POST['op'])));
        $op = "";
        $search = "";
    } else {
      $op = $_POST["op"];
      $search = $_POST["search"];
    }

    if($op != "get" &&
       $op != "index" &&
       $op != "vindex")
      return $this->rc->output->command(
        'plugin.pks_search',
        array('message' => "ERR: Invalid operation",
              'op' => htmlspecialchars($op)));

    if($op == "index") {
      $ch = curl_init();
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($ch, CURLOPT_URL, "http://pool.sks-keyservers.net:11371/pks/lookup?op=index&search={$search}");
      $result = curl_exec($ch);
      $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);

      if($status == 200) {
        // TODO Fix search regex to match 32/64-bit str
        preg_match_all("/\/pks\/lookup\?op=vindex&search=(.*)\">(.*)<\/a>/", $result, $m);

        if(count($m) > 0) {
          $found = array();
          for($i = 0; $i < count($m[0]); $i++)
            $found[] = array($m[1][$i], $m[2][$i]);
          return $this->rc->output->command(
            'plugin.pks_search',
            array('message' => json_encode($found),
                  'op' => htmlspecialchars($op)));
        }
      } else {
        preg_match("/Error handling request: (.*)<\/body>/", $result, $m);
        return $this->rc->output->command(
          'plugin.pks_search',
          array('message' => "ERR: " . htmlspecialchars($m[1]),
                'op' => htmlspecialchars($op)));
      }
    } elseif($op == "get") {
      if(preg_match("/^0x[0-9A-F]{8}$/i", $search)) {
        define("32_BIT_KEY", true);
        define("64_BIT_KEY", false);
      } elseif(preg_match("/^0x[0-9A-F]{16}$/i", $search)) {
        define("32_BIT_KEY", false);
        define("64_BIT_KEY", true);
      } else {
        return $this->rc->output->command(
          'plugin.pks_search',
          array('message' => "ERR: Incorrect search format for this operation",
                'op' => htmlspecialchars($op)));
      }

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($ch, CURLOPT_URL, "http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search={$search}");
      $result = curl_exec($ch);
      $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);

      if($status == 200) {
        preg_match_all("/-----BEGIN PGP PUBLIC KEY BLOCK-----(.*)-----END PGP PUBLIC KEY BLOCK-----/s", $result, $m);
        return $this->rc->output->command(
          'plugin.pks_search',
          array('message' => json_encode($m),
                'op' => htmlspecialchars($op)));
      }
    }
  }

// TODO: Store pubkeys in rc storage
// Don't sync upstream, it hurts decentralization
  function hkp_add() {
    header("HTTP/1.1 501 Not Implemented");
    die();
  }

  /**
   * Saves the public key to a temporary file so we can send it as attachment
   */
  function pubkey_save() {
    $rcmail = rcmail::get_instance();
    $temp_dir = unslashify($rcmail->config->get('temp_dir'));
    $file = $temp_dir."/".md5($_SESSION['username']).".asc";
    if(file_exists($file)) {
      $pubkey = trim(get_input_value('_pubkey', RCUBE_INPUT_POST));
      file_put_contents($file, $pubkey);
    }
  }

  /**
   * Handler for preferences_sections_list hook.
   * Add new section to preferences for encryption
   *
   * @param array Original params
   * @return array Modified params
   */
  function preferences_sections_list($p) {
      $this->add_texts('locallization/', false);
      $p['list']['openpgp_prefs'] = array(
          'id'      => 'openpgp_prefs',
          'section' => Q($this->gettext('openpgp_title'))
      );
      return ($p);
  }


  /**
   * Handler for preferences_list hook.
   * Adds options blocks into Compose settings sections in Preferences.
   *
   * @param array Original parameters
   * @return array Modified parameters
   */
  function preferences_list($p) {
    if (!get_input_value('_framed', RCUBE_INPUT_GPC) && $args['section'] == 'openpgp_prefs') {
        $p['blocks'][$args['section']]['options'] = array (
            'title'     => '',
            'content'   => html::tag('div', array('id' => 'pm_dummy'), '')
        );
        return $p;
    }

    if ($p['section'] == 'openpgp_prefs') {
      $p['blocks']['openpgp']['name'] = $this->gettext('openpgp_options');

      if (!isset($no_override['openpgp_enabled'])) 
      {
         $field_id = 'rcmfd_openpgp_enabled';
         $enabled = new html_checkbox(
             array('name' => '_encEnabled', 
                    'id' => $field_id,
                    'value' => 1,
                    'onchange' => "$('#rcmfd_auto_attach_key').prop('disabled', !(this.checked)); " .
                                  "$('#rcmfd_warn_unencrypted').prop('disabled', !(this.checked)); " .
                                  "$('#rcmfd_encrypt').prop('disabled', !(this.checked)); " .
                                  "$('#rcmfd_sign').prop('disabled', !(this.checked))"
         ));
         $p['blocks']['openpgp']['options']['enabled'] = array(
            'title' => html::label($field_id, Q($this->gettext('openpgp_enabled'))),
            'content' => $enabled->show($this->rc->config->get('openpgp_enabled', 1)),
         );
      } 

      /* Warn on encrypted checkbox */
      $field_id = 'rcmfd_warn_unencrypted';
      $warn = new html_checkbox(
         array('name' => '_warn', 
               'id' => $field_id, 
               'value' => 1, 
               'disabled' => !$this->is_enabled()
            )
         );

      $p['blocks']['openpgp']['options']['warn'] = array(
        'title' => html::label($field_id, Q($this->gettext('warn_on_unencrypted'))),
        'content' => $warn->show($this->rc->config->get('warn_on_unencrypted', false)?1:0),
    );

      /* Auto attach checkbox */
      $field_id = 'rcmfd_auto_attach_key';
      $attach = new html_checkbox(
         array('name' => '_attachKey', 
               'id' => $field_id, 
               'value' => 1, 
               'disabled' => !$this->is_enabled()
            )
         );

      $p['blocks']['openpgp']['options']['attachKey'] = array(
        'title' => html::label($field_id, Q($this->gettext('always_attachKey'))),
        'content' => $attach->show($this->rc->config->get('attachKey', false)?1:0),
      );

      /* Encrypt default checkbox */
      $field_id = 'rcmfd_encrypt';
      $encrypt = new html_checkbox(
         array('name' => '_encrypt', 
               'id' => $field_id, 
               'value' => 1,  
               'disabled' => !$this->is_enabled()
            )
      );      
      $p['blocks']['openpgp']['options']['encrypt'] = array(
        'title' => html::label($field_id, Q($this->gettext('always_encrypt'))),
        'content' => $encrypt->show($this->rc->config->get('encrypt', false)?1:0),
      );

      /* Sign default checkbox */
      $field_id = 'rcmfd_sign';
      $sign = new html_checkbox(
         array('name' => '_sign', 
               'id' => $field_id, 
               'value' => 1, 
               'disabled' => !$this->is_enabled()
            )
         );      
      $p['blocks']['openpgp']['options']['sign'] = array(
        'title' => html::label($field_id, Q($this->gettext('always_sign'))),
        'content' => $sign->show($this->rc->config->get('sign', false)?1:0),
      );

    }

    return $p;
  }

  /**
   * Handler for preferences_save hook.
   * Executed on Compose settings form submit.
   *
   * @param array Original parameters
   * @return array Modified parameters
   */
  function preferences_save($p) {
    if ($p['section'] == 'openpgp_prefs') 
    {
      $p['prefs']['encrypt'] = get_input_value('_encrypt', RCUBE_INPUT_POST) ? true : false;
      $p['prefs']['sign'] = get_input_value('_sign', RCUBE_INPUT_POST) ? true : false;
      $p['prefs']['attachKey'] = get_input_value('_attachKey', RCUBE_INPUT_POST) ? true : false;
      $p['prefs']['warn_on_unencrypted'] = get_input_value('_warn', RCUBE_INPUT_POST) ? true : false;
      $p['prefs']['openpgp_enabled'] = get_input_value('_encEnabled', RCUBE_INPUT_POST) ? true: false;
    }
    return $p;
  }

  /**
   * Handler for message_compose hook
   * Creates a dummy publick key attachment
   */
  function message_compose($args) {
    if ($this->is_enabled() && ($this->rc->config->get('attachKey', false)) && ( $f = $this->create_pubkey_dummy() )) {
      $args['attachments'][] = array('path' => $f, 'name' => "pubkey.asc", 'mimetype' => "text/plain");
    }
    return $args;
  }

  /**
   * Handler for message_sent hook
   * Deletes the public key from the server
   */
  function unlink_pubkey($args) {
    $rcmail = rcmail::get_instance();
    $temp_dir = unslashify($rcmail->config->get('temp_dir'));
    $file = $temp_dir."/".md5($_SESSION['username']).".asc";
    if(file_exists($file)) {
      @unlink($file);
    }
  }

  /**
   * Creates a dummy public key file
   */
  function create_pubkey_dummy() {
    $rcmail = rcmail::get_instance();
    $temp_dir = unslashify($rcmail->config->get('temp_dir'));
    if (!empty($temp_dir)) {
      $file = $temp_dir."/".md5($_SESSION['username']).".asc";
      if(file_exists($file))
        @unlink($file);
      if (file_put_contents($file, " ")) {
        return $file;
      }
    }
    return false;
  }
}
