<?php
/*
+-------------------------------------------------------------------------+
| OpenPGP.js implemented in Roundcube                                     |
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
| Author: Niklas Femerstrand <nik@qnrq.se>                                |
+-------------------------------------------------------------------------+
*/

class openpgpjs extends rcube_plugin
{
	function init()
	{
		$this->add_hook('render_page', array($this, 'render_page'));
		$this->add_hook('user_create', array($this, 'user_create'));
		$this->register_action('plugin.pks_search', array($this, 'pks_search'));
	}

	function render_page($params)
	{	
		if($params['template'] == 'compose' || $params['template'] == 'message')
		{
			$this->include_script('js/jquery.cookie.js');
			$this->include_script('js/openpgp.min.js');
			$this->include_script('js/openpgpjs.js');
			$this->include_stylesheet('css/openpgpjs.css');
		}

		return $params;
	}

	// Create default identity, required as pubkey metadata
	function user_create($params)
	{
		$params['user_name'] = preg_replace("/@.*$/", "", $params['user']);
		$params['user_email'] = $params['user'];
		return $params;
	}

	/**
	 * This Public Key Server proxy is written to circumvent Access-Control-Allow-Origin
	 * limitations. It also provides a layer of security as HTTP PKS normally
	 * doesn't support HTTPS; essentially preventing MITM if the Roundcube installation
	 * is configured to use HTPS. For more details see the following doc:
	 * http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00.
	 */
	function pks_search()
	{
		if(!isset($_POST['op']))
		{
			$rcmail->output->command('plugin.pks_search', array('message' => "ERR: Missing param"));
			return;
		}

		$rcmail = rcmail::get_instance();
		//TODO switch to curl, read http status code
		if($_POST['op'] == "index")
		{
			$return = "";
			$result = file_get_contents("http://pgp.mit.edu:11371/pks/lookup?op=index&search={$_POST['search']}");
			preg_match_all("/\/pks\/lookup\?op=vindex&search=(.*)\">(.*)<\/a>/", $result, $m);
			if(count($m > 0))
			{
				for($i = 0; $i < count($m[0]); $i++)
					$return .= "{$m[1][$i]}:{$m[2][$i]}\n";
			}
		}
		elseif($_POST['op'] == "get")
		{
			$return = file_get_contents("http://pgp.mit.edu:11371/pks/lookup?op=get&search={$_POST['search']}");
		}

		$rcmail->output->command('plugin.pks_search', array('message' => $return, 'op' => $_POST['op']));
		return;
	}
}
