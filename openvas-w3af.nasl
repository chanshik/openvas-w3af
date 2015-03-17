##############################################################################
# OpenVAS Vulnerability Test
#
# Assess web security with w3af
#
# Authors:
# Vlatko Kosturjak <kost..at..linux.hr>
# Support w3af 1.6.x commands added by 
# Chan Shik Lim <chanshik..at..gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This plugin uses w3af (w3af_console to be exact) to find  
web security issues.

See the preferences section for w3af options.

Note that OpenVAS is using limited set of w3af options.
Therefore, for more complete web assessment, you should
use standalone w3af tool for deeper/customized checks.";

if (description)
{
	script_id(80109);
	script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
	script_version("$Revision: 1000 $");
	script_tag(name:"last_modification", value:"$Date: 2015-02-09 15:46:01 +0100 (Mon, 09 Feb 2015) $");
	script_tag(name:"creation_date", value:"2009-10-18 22:12:25 +0200 (Sun, 18 Oct 2009)");
	script_tag(name:"cvss_base", value:"0.0");
	script_name("w3af (NASL wrapper)");

	desc = "
	Summary:
	" + tag_summary;

	script_description(desc);

	script_summary("Assess web security with w3af");

	script_category(ACT_GATHER_INFO);

	script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
	script_family("Web application abuses");

	script_add_preference(name: "Path of w3af", type: "entry", value: "/opt/w3af/w3af_console");
	script_add_preference(name: "Ports", type: "entry", value: "80,443");
	script_add_preference(name: "Seed URL", type: "entry", value: "");
	script_add_preference(
		name: "Profile", type:"radio",
		value:"fast_scan;sitemap;web_infrastructure;OWASP_TOP10;audit_high_risk;bruteforce;full_audit");
	script_add_preference(name: "Debug", type: "entry", value: "False");

	script_dependencies("find_service.nasl", "httpver.nasl", "http_login.nasl");
	script_require_ports("Services/www", 80, 8000, 8080, 4000, 5000);
	script_require_ports("Services/https", 443);
	script_timeout(0); 

	script_tag(name : "summary" , value : tag_summary);
	exit(0);
}

include("http_func.inc");
include("openvas-https.inc");

path_of_w3af = script_get_preference("Path of w3af");
if (! path_of_w3af) {
	cmd_w3af = "/opt/w3af/w3af_console";
}
else {
	cmd_w3af = path_of_w3af;
}

if (! file_stat(cmd_w3af)) {
	error_msg = "Failed find w3af_console executable file: " + cmd_w3af;

	log_message(port: 0, data: error_msg);
	exit(10);
}

use_profile = script_get_preference("Profile");
if (! use_profile) {
	use_profile = "fast_scan";
}

ports_str = script_get_preference("Ports");
if (! ports_str) {
	ports = make_list(80, 443);
}
else {
	ports = split(ports_str, sep: ",", keep: 0);
}

debug_str = script_get_preference("Debug");
is_debug = FALSE;
if (chomp(tolower(debug_str)) == "true") {
	is_debug = TRUE;
}

is_debug = TRUE;

foreach port_num (ports) {
	if (is_debug) {
		start_msg = "Checking port: " + int(port_num);
		if (get_port_state(port_num)) {
			start_msg += " (OPEN)";
		}
		else {
			start_msg += " (CLOSED)";
		}
		log_message(port: port_num, data: start_msg);
	}

	if (! get_port_state(int(port_num))) {
		continue;
	}

	encaps = get_port_transport(port_num);
	if (IS_ENCAPS_SSL(encaps)) {
		http_prefix = "https";
	}
	else {
		http_prefix = "http";
	}

	http_ver = get_kb_item("http/" + port);
	if (http_ver == "11") {
		http_host = get_host_name();
	}
	else {
		http_host = get_host_ip();
	}
	http_url = http_prefix + "://" + http_host + ":" + port_num;

	seed = script_get_preference("Seed URL");
	if (seed) {
		if (ereg(pattern: "^/", string: seed)) {
			http_url = http_url + seed;
		}
		else {
			http_url = http_url + "/" + seed;
		}
	}

	output_basename = get_tmp_dir() + "openvas-w3af-" + get_host_ip() + "-" + port_num;
	report_filename = output_basename + '.txt';
	cmd_filename = output_basename + '.cmd';
	http_filename = output_basename + '-http.txt';

	cmd_data = "profiles use " + use_profile + '\n';
	cmd_data += 'plugins\n';
	cmd_data += 'output text_file\n';
	cmd_data += 'output config text_file\n';

	if (report_verbosity > 0) {
		cmd_data += 'set verbose True\n';
	}
	else {
		cmd_data += 'set verbose False\n';
	}
	cmd_data += 'set output_file ' + report_filename + '\n';
	cmd_data += 'set http_output_file ' + http_filename + '\n';
	cmd_data += 'back\n';
	cmd_data += 'back\n';

	if (is_debug) {
		preparing_msg = "URL: " + http_url + " (ENCAPS: " + encaps + ")\n";
		preparing_msg += "Report: " + report_filename + "\nCmd: " + cmd_filename;

		log_message(port: port_num, data: preparing_msg);
	}

	cmd_data += 'target set target ' + http_url + '\n';
	cmd_data += 'start\n';
	cmd_data += 'exit\n';

	if (is_debug) {
		log_message(port: port_num, data: "w3af commands: \n" + cmd_data);
	}

	fwrite(data: cmd_data, file:cmd_filename);

	r = pread(cmd: cmd_w3af, argv: make_list(cmd_w3af, "-s", cmd_filename));
	if (! r) {
		log_message(port: port_num, data: "Failed execute w3af.");

		exit(20);
	}

	if (! file_stat(report_filename)) {
		log_message(port: port_num, data: "Failed read scanning report: " + report_filename);

		exit(30);
	}

	result = fread(report_filename);
	report = "w3af report:\n";
	report += result + "\n";

	if ("- vulnerability]" >< report) {
		security_warning(port: port_num, data: report);
	}
	else {
		log_message(port: port_num, data: report);
	}

	if (file_stat(cmd_filename)) {
		unlink(cmd_filename);
	}
	if (file_stat(report_filename)) {
		unlink(report_filename);
	}
	if (file_stat(http_filename)) {
		unlink(http_filename);
	}
}
