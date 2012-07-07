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
	public $task = 'mail';

	function init()
	{
		$this->add_hook('render_page', array($this, 'render_page'));
		$this->register_action('plugin.someaction', array($this, 'pass_compare'));
		$this->register_action('openpgpjs.pks_proxy', array($this, 'pks_proxy'));
	}
	
	function render_page($params)
	{	
		if($params['template'] == 'compose' || $params['template'] == 'message')
		{
			$this->include_script('js/jquery.cookie.js');
			$this->include_script('js/openpgp.min.js');
			$this->include_script('js/sjcl.js');
			$this->include_script('js/uuid.js');
			$this->include_script('js/openpgpjs.js');
			$this->include_stylesheet('css/openpgpjs.css');
		}

		return $params;
	}

	/**
	 * Determine if the provided passphrase equals the password of the authenticated
	 * user. Deny key generation on JavaScript level if so is the case.
	 */
	function pass_compare()
	{
		$rcmail = rcmail::get_instance();
		if($_POST['passphrase'] == $rcmail->decrypt($_SESSION['password']))
			$ret = true;
		else
			$ret = false;
		$rcmail->output->command('plugin.somecallback', array('message' => $ret));
	}

	/**
	 * Public key server proxy used to circument Access-Control-Allow-Origin.
	 * If the the Roundcube service is running on HTTPS this function also helps
	 * anonymizing who the user is emailing as PKS uses HTTP by default.
	 */
	function pks_proxy()
	{
		$rcmail = rcmail::get_instance();
		$rcmail->output->command('openpgpjs.pks_proxy_callback', array('message' => 'test'));
	}
}
