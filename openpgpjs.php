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
}
