/*

#
#   Target Redirector Burp extension
#
#   Copyright (C) 2016-2018 Paul Taylor
#   fork: Tim Abdiukov (2024)
#

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this output_file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

 */

package burp

import java.awt.event.ActionEvent
import java.awt.event.ActionListener

import java.net.InetAddress

import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JOptionPane

class Redirector(val id: Int, val view: UI, var host_header: Any?, var original: Map<String, Any?>, var replacement: Map<String, Any?>, var flags: Map<String, Boolean>) {

    companion object {

        const val HOST_PORT_SPECIFIED = 0
        const val HOST_PORT_IGNORE = 1
        const val HOST_PORT_REGEX = 2

        const val PROTO_BOTH_IGNORE = 0
        const val PROTO_HTTP = 1
        const val PROTO_HTTPS = 2

        const val HOST_HEADER_IGNORE = 0
        const val HOST_HEADER_ORIGINAL = 1
        const val HOST_HEADER_NEW = 2
        const val HOST_HEADER_SPECIFIED = 3

        var instances = mutableListOf<Redirector>()
        lateinit var view: UI

        fun notification(message: String) {
            view.notification(message, "Redirector")
        }

        fun add_instance(host_header: Any?, original_data: Map<String, Any?>, replacement_data: Map<String, Any?>, flags: Map<String, Boolean>) {
            val id = instances.size
            instances.add(Redirector(id, view, host_header, original_data, replacement_data, flags))
            notification("Initialising new redirector #" + id + " (total " + instances.size + ")")
        }

        fun remove_instance(id: Int) {
            instances.removeAt(id)
            notification("Removed redirector #" + id + " (new total " + instances.size + ")")
        }

        fun instance_add_or_remove(view_arg: UI, host_header: Any?, original_data: Map<String, Any?>, replacement_data: Map<String, Any?>, flags: Map<String, Boolean>) : Int {

            view = view_arg

            if (instances.isEmpty()) {
                add_instance(host_header, original_data, replacement_data, flags)
            }

            val instance_id = instances.size - 1
            val instance = instances[instance_id]
            var result: Int

            if (!instance.toggle()) {
                Redirector.remove_instance(instance_id)
                result = -1
            } else {
                result = instance_id
            }

            listener.toggle_registration()
            return result
        }

        class HttpListener() : IHttpListener {

            var registered = false

            fun deregister() {
                BurpExtender.cb.removeHttpListener(this)
                notification("Listener removed")
                registered = false
            }

            fun register() {
                BurpExtender.cb.registerHttpListener(this)
                registered = true
                notification("Listener enabled")
            }

            fun toggle_registration() {
                when {
                    instances.isEmpty()    && !registered       -> return
                    instances.isEmpty() /* && registered */     -> deregister()
                    registered  /* && !instances.isEmpty() */   -> return
                    !registered /* && !instances.isEmpty() */   -> register()
                }
            }

            override fun processHttpMessage(
                toolFlag: Int,
                messageIsRequest: Boolean,
                messageInfo: IHttpRequestResponse) {
                if (instances.isEmpty() || !registered) { return }

                val current_url = "${messageInfo.httpService.protocol}://${messageInfo.httpService.host}:${messageInfo.httpService.port}"

                if (messageIsRequest) {
                    notification("----->")
                    notification("> Incoming request to: ${current_url}")
                    for (instance in instances) {
                        if (instance.active) instance.perform_redirect(messageInfo)
                    }
                }
                else {
                    notification("<-----")
                    notification("< Incoming response from: ${current_url}")
                }
            }
        }

        var listener = HttpListener()

    }

    var active = false
    var suppress_popup = false
    var redirector_id = "Redirector#" + id

    fun fetch_input(text: String, item: String?) = view.fetch_input(
                                                    text,
                                                    item,
                                                    redirector_id
                                                )

    fun notification(text: String, popup: Boolean = false, suppress_next: Boolean = false) {
        var _popup = false

        if (popup && suppress_popup){
            suppress_popup = false
        } else _popup = popup

        if (suppress_next) suppress_popup = true

        view.notification(text, redirector_id, _popup)
    }

    var replacement_host = ""
    var replacement_port = -1
    var replacement_protocol = ""

    var do_redirect_scheme: Boolean = false
    var do_redirect_transport: Boolean = false


    fun original_url(): String {
        val proto = when (original["protocol"]) {
                PROTO_BOTH_IGNORE -> "[http,https]"
                PROTO_HTTP -> "http"
                PROTO_HTTPS -> "https"
                else -> "[http,https]"
        }
        val host = when (original["host_mode"]) {
                HOST_PORT_IGNORE -> "[any host/ip]"
                HOST_PORT_SPECIFIED -> original["host"].toString()
                HOST_PORT_REGEX -> "[REGEX/${original["host"]}/]"
                else -> "[any host/ip]"
        }
        val port = when (original["port_mode"]) {
                HOST_PORT_IGNORE -> "[0-65535]"
                HOST_PORT_SPECIFIED -> original["port"].toString()
                HOST_PORT_REGEX -> "[REGEX/${original["port"]}/]"
                else -> "[0-65535]"
        }
        return "${proto}://${host}:${port}"
    }

    fun replacement_url(): String {
        do_redirect_scheme = flags["do_redirect_scheme"] ?: false
        // notification("do_redirect_scheme: "+do_redirect_scheme.toString())
        val proto =  if (do_redirect_scheme) {
            when (replacement["protocol"]) {
                    PROTO_BOTH_IGNORE -> "[keep]"
                    PROTO_HTTP -> "http"
                    PROTO_HTTPS -> "https"
                    else -> "[keep]"
            }
        } else {
            "[keep]"
        }

        val host = when (replacement["host_mode"]) {
                HOST_PORT_IGNORE -> "[keep]"
                HOST_PORT_SPECIFIED -> replacement["host"].toString()
                else -> "[keep]"
        }
        val port = when (replacement["port_mode"]) {
                HOST_PORT_IGNORE -> "[keep]"
                HOST_PORT_SPECIFIED -> replacement["port"].toString()
                else -> "[keep]"
        }
        return "${proto}://${host}:${port}"
    }

    fun getbyname(name: String?, popup_on_error: Boolean = false, suppress_next: Boolean = false): Boolean {
        try {
            InetAddress.getByName(name)
            return true
        }
        catch (UnknownHostException: Exception) {
            notification("Hostname/IP \"${name}\" appears to be invalid.", popup_on_error, suppress_next)
            return false
        }
    }

    fun toggle_dns_correction() { // *** DNS correction only applied with specifed hostnames

        if (active) {
            if (original["host_mode"] == HOST_PORT_SPECIFIED) BurpExtender.Dns_Json.remove(original["host"].toString())
            return
        } else if (original["host_mode"] == HOST_PORT_SPECIFIED && !getbyname(original["host"].toString(), false)) {
            notification("Hostname/IP \"${original["host"]}\" appears to be invalid.\n\n" +
                "An entry will be added to\nProject options / Hostname Resolution\n" +
                "to allow invalid hostname redirection.", true)

            BurpExtender.Dns_Json.add(original["host"].toString())

            view.toggle_dns_correction(true)
        } else {
            view.toggle_dns_correction(false)
        }
    }

    fun host_port_valid(host_port: Map<String, Any?>, field: String): Boolean {
        return when (host_port["${field}_mode"]) {
            HOST_PORT_SPECIFIED ->  if (field == "host") !host_port[field].toString().isNullOrBlank()
                                    else host_port[field].toString().toIntOrNull() != null
            HOST_PORT_IGNORE -> true
            HOST_PORT_REGEX -> host_port[field].toString().toRegex().toString() > ""  // *** replace with proper check for valid regex
            else -> false
        }
    }

    fun activate(): Boolean {

        if (
            host_port_valid(original, "host") &&
            host_port_valid(original, "port") &&
            host_port_valid(replacement, "host") &&
            host_port_valid(replacement, "port") &&
            getbyname(replacement["host"].toString(), true, true)
            ) {
                toggle_dns_correction()
                return true
        } else {
                return false
        }
    }

    fun get_new_host_header(hn_old: String, hn_original: String, hn_replacement: String): String {
        return when (host_header) {
            HOST_HEADER_IGNORE -> hn_old
            HOST_HEADER_ORIGINAL -> hn_original
            HOST_HEADER_NEW -> hn_replacement
            else -> host_header.toString()
        }
    }

    fun host_header_set(messageInfo: IHttpRequestResponse, original_hostname: String){

        val host_regex ="^(?i)(Host:)( {0,1})(.*)$".toRegex(RegexOption.IGNORE_CASE)

        var old_header_set = false
        var old_host: String?
        var new_host: String

        var new_headers = mutableListOf<String>()

        var requestInfo = BurpExtender.cb.helpers.analyzeRequest(messageInfo)

        for (old_header in requestInfo.headers) {

            if (old_header_set) {
                new_headers.add(old_header)
                continue
            } else {
                old_host = host_regex.matchEntire(old_header)?.groups?.get(3)?.value
                if (old_host == null) {
                    new_headers.add(old_header)
                    continue
                } else {
                    if (host_header != HOST_HEADER_IGNORE) {
                        new_host = get_new_host_header(old_host, original_hostname, messageInfo.httpService.host.lowercase())
                        if (old_host == new_host) {
                            notification("Old host header is already set to ${new_host}, no change required")
                            return
                        } else {
                            notification("> Host header changed from ${old_host} to ${new_host}")
                            new_headers.add("Host: ${new_host}")
                            old_header_set = true
                        }
                    } else {
                        notification("Old host header is set to ${old_host} and host header is not set to be changed")
                        return
                    }
                }
            }
        }

        if (!old_header_set) {
            notification("> Existing host header not found, maybe HTTP/1.0. No host header added.")
        }

        messageInfo.request = BurpExtender.cb.helpers.buildHttpMessage(
                                    new_headers,
                                    messageInfo.request.copyOfRange(
                                        requestInfo.bodyOffset,
                                        messageInfo.request.size
                                    )
                                )
    }

    fun perform_redirect(messageInfo: IHttpRequestResponse) {

        notification("> Matching against URL: ${original_url()}")

        if (
            when (original["host_mode"]) {
                    HOST_PORT_IGNORE -> true
                    HOST_PORT_SPECIFIED -> if (messageInfo.httpService.host.lowercase() == original["host"].toString()) true else false
                    HOST_PORT_REGEX -> if (original["host"].toString().toRegex(RegexOption.IGNORE_CASE).matches(messageInfo.httpService.host)) true else false
                    else -> false
            }
            && when (original["port_mode"]) {
                    HOST_PORT_IGNORE -> true
                    HOST_PORT_SPECIFIED -> if (messageInfo.httpService.port == original["port"].toString().toInt()) true else false
                    HOST_PORT_REGEX -> if (original["port"].toString().toRegex(RegexOption.IGNORE_CASE).matches(messageInfo.httpService.port.toString())) true else false
                    else -> false
            }
            && when (original["protocol"]) {
                    PROTO_BOTH_IGNORE -> true
                    PROTO_HTTP -> if (messageInfo.httpService.protocol == "http") true else false
                    PROTO_HTTPS -> if (messageInfo.httpService.protocol == "https") true else false
                    else -> false
            }
        ) {

            when (replacement["host_mode"]) {
                    HOST_PORT_IGNORE -> replacement_host = messageInfo.httpService.host.lowercase()
                    HOST_PORT_SPECIFIED -> replacement_host = replacement["host"].toString()
            }
            when (replacement["port_mode"]) {
                    HOST_PORT_IGNORE -> replacement_port = messageInfo.httpService.port.toString().toInt()
                    HOST_PORT_SPECIFIED -> replacement_port = replacement["port"].toString().toInt()
            }

            do_redirect_transport = flags["do_redirect_transport"] ?: false
            // notification("do_redirect_transport: "+do_redirect_transport.toString())
            if (do_redirect_transport) {
                when (replacement["protocol"]) {
                        PROTO_BOTH_IGNORE -> replacement_protocol = messageInfo.httpService.protocol
                        PROTO_HTTP -> replacement_protocol = "http"
                        PROTO_HTTPS -> replacement_protocol = "https"
                }
            } else {
                replacement_protocol = messageInfo.httpService.protocol
            }

            val original_hostname = messageInfo.httpService.host.lowercase()

            notification(
                "> Target changed from ${messageInfo.httpService.protocol}://${messageInfo.httpService.host}:${messageInfo.httpService.port} to ${replacement_url()}"
            )

            messageInfo.httpService = BurpExtender.cb.helpers.buildHttpService(
                replacement_host,
                replacement_port,
                replacement_protocol
            )

            host_header_set(messageInfo, original_hostname)

        } else {
            notification("> Target not changed to ${replacement_url()}")
        }
    }

    fun toggle(): Boolean {

        if (active) {
            toggle_dns_correction()
            active = false
        } else {
            if (activate()) {
                active = true
                notification("Redirection Activated for:\n${original_url()}\nto:\n${replacement_url()}", false)
            } else {
                active = false
                notification("Invalid hostname and/or port settings.", true)
            }
        }
        return active
    }
}

/*

         *****     *****        ********
        ******     ******        ******
        ******     ******        ******
        ******     ******        ******
         ******   ******         ******
          *************          ******
           ***********          ********
*/

class UI() : ITab {

    override public fun getTabCaption() = "Target Redirector Fork"
    override public fun getUiComponent() = mainpanel

    val mainpanel = JPanel()
    val innerpanel = JPanel()

    val subpanel = JPanel()
    val activationpanel = JPanel()

    inner class redirect_panel(val host: String, val original: Boolean) : JPanel() {

        val text_host = JTextField(12)
        val text_port = JTextField(5)

        val host_array =
            if (original) arrayOf(
                "Redirect from hostname/IP:",
                "Redirect any hostname/IP",
                "Redirect hostname/IP regex:"
            ) else arrayOf(
                "To destination hostname/IP:",
                "Without changing hostname/IP"
            )

        val port_array =
            if (original) arrayOf(
                "specific port:",
                "redirect any port",
                "specific port regex:"
            ) else arrayOf(
                "redirect to specific port:",
                "without changing port"
            )

        val protocol_array =
            if (original) arrayOf(
                "redirect both HTTP/S",
                "only redirect HTTP",
                "only redirect HTTPS"
            ) else arrayOf(
                "without changing HTTP/S",
                "redirect as HTTP",
                "redirect as HTTPS"
            )

        val dropdown_host = JComboBox<String>(host_array)
        val dropdown_port = JComboBox<String>(port_array)
        val dropdown_proto = JComboBox<String>(protocol_array)

        fun combo_click(selected: Int, textbox: JTextField) {
            if (selected == Redirector.HOST_PORT_IGNORE) textbox.setVisible(false)
            else textbox.setVisible(true)
            textbox.requestFocus()
            refresh()
        }

        init {
            dropdown_host.addActionListener(object: ActionListener {
                override fun actionPerformed(e: ActionEvent) {
                    if (!true && e.actionCommand == "") {}  // hack to remove compiler warning about e argument being unused
                    combo_click(dropdown_host.selectedIndex, text_host)
                }
            })
            dropdown_port.addActionListener(object: ActionListener {
                override fun actionPerformed(e: ActionEvent) {
                    if (!true && e.actionCommand == "") {}  // hack to remove compiler warning about e argument being unused
                    combo_click(dropdown_port.selectedIndex, text_port)
                }
            })

            add(dropdown_host)
            add(text_host)
            add(dropdown_port)
            add(text_port)
            add(dropdown_proto)
        }

        fun get_data(): Map<String, Any> {

            val data = mutableMapOf<String, Any>()

            if (dropdown_host.selectedIndex == Redirector.HOST_PORT_SPECIFIED) text_host.text = text_host.text.lowercase()
            else if (dropdown_host.selectedIndex == Redirector.HOST_PORT_IGNORE) text_host.text = ""
            if (dropdown_port.selectedIndex == Redirector.HOST_PORT_IGNORE) text_port.text = ""

            data["host"] = text_host.text
            data["port"] = text_port.text
            data["protocol"] = dropdown_proto.selectedIndex
            data["host_mode"] = dropdown_host.selectedIndex
            data["port_mode"] = dropdown_port.selectedIndex

            return data
        }

        fun get_flags(): Map<String, Boolean> {
            val data = mutableMapOf<String, Boolean>()

            data["do_redirect_scheme"] = do_redirect_scheme_jcheckbox.isSelected
            data["do_redirect_transport"] = do_redirect_transport_jcheckbox.isSelected

            return data
        }

        fun toggle_lock(locked: Boolean) {
            text_host.setEditable(locked)
            text_port.setEditable(locked)
            dropdown_proto.setEnabled(locked)
            dropdown_host.setEnabled(locked)
            dropdown_port.setEnabled(locked)
            do_redirect_scheme_jcheckbox.setEnabled(locked)
            do_redirect_transport_jcheckbox.setEnabled(locked)
        }
    }

    val redirect_panel_original = redirect_panel("Redirect host/IP:", true)
    val redirect_panel_replacement = redirect_panel("to destination host/IP:", false)

    fun toggle_active(active: Boolean) {
        redirect_button.text = if (active) "Remove redirection" else "Activate redirection"
        redirect_panel_original.toggle_lock(active.not())
        redirect_panel_replacement.toggle_lock(active.not())
        dropdown_hostheader.setEnabled(active.not())
        text_hostheader.setEnabled(active.not())
        if (!active) { cbox_dns_correction.setSelected(false) }
    }

    fun toggle_dns_correction(enabled: Boolean) {
        cbox_dns_correction.setSelected(enabled)
    }

    val redirect_panel_options = JPanel()

    val dropdown_hostheader = JComboBox(
            arrayOf(
                "Without changing HTTP Host header",
                "Pre-redirection hostname(:port)",
                "Post-redirection hostname(:port)",
                "Set custom HTTP host header value:"
            )
        )

    val text_hostheader = JTextField(18)

    fun dropdown_hostheader_get_data(): Any = when (dropdown_hostheader.selectedIndex) {
            Redirector.HOST_HEADER_IGNORE,
            Redirector.HOST_HEADER_ORIGINAL,
            Redirector.HOST_HEADER_NEW
                    -> {
                        text_hostheader.text = ""
                        dropdown_hostheader.selectedIndex
                    }
            else -> { text_hostheader.text }
        }

    fun dropdown_hostheader_click() {
        when (dropdown_hostheader.selectedIndex) {
            Redirector.HOST_HEADER_SPECIFIED -> text_hostheader.setVisible(true)
            else -> text_hostheader.setVisible(false)
        }
        text_hostheader.requestFocus()
        refresh()
    }

    val cbox_dns_correction = JCheckBox("Invalid original hostname DNS correction")

    val do_redirect_scheme_jcheckbox = JCheckBox("Redirect scheme", true)
    val do_redirect_transport_jcheckbox = JCheckBox("Redirect transport", true)

    val redirect_button = JButton("Activate Redirection")

    fun redirect_button_pressed() {

        val instance_id = Redirector.instance_add_or_remove(
                this,
                dropdown_hostheader_get_data(),
                redirect_panel_original.get_data(),
                redirect_panel_replacement.get_data(),
                redirect_panel_replacement.get_flags()
            )

        toggle_active(
            if (instance_id > -1) true else false
        )
    }

    fun popup_input(text: String, item: String?) = JOptionPane.showInputDialog(
                                                    mainpanel,
                                                    text,
                                                    "Burp / Target Redirector",
                                                    JOptionPane.PLAIN_MESSAGE,
                                                    null,
                                                    null,
                                                    item
                                                )

    fun popup_notice(text: String) = JOptionPane.showMessageDialog(
                                        mainpanel,
                                        text,
                                        "Burp / Target Redirector",
                                        JOptionPane.WARNING_MESSAGE
                                    )

    fun log(text: String, source: String) = BurpExtender.cb.printOutput(
                                                "[" + source + "] " + text.replace("\n", " ")
                                            )

    fun fetch_input(text: String, item: String?, source: String) : String
     {
        var result = popup_input(text, item)
        var log_result : String

        if (result == null) {
            result = ""
            log_result = "<CANCELLED>"
        } else if (result == "") {
            log_result = "<EMPTY>"
        } else log_result = result.toString()

        log(text + ": " + log_result, source)
        return result.toString()
    }

    fun notification(text: String, source: String, popup: Boolean = false) {
        if (popup) popup_notice(text)
        log(text, source)
    }

    fun refresh(){
        mainpanel.validate();
        mainpanel.repaint();
        subpanel.validate();
        subpanel.repaint();
        innerpanel.validate();
        innerpanel.repaint();
        redirect_panel_options.validate();
        redirect_panel_options.repaint();
    }

    init {

        mainpanel.border = BorderFactory.createEmptyBorder(20, 20, 20, 20)

        mainpanel.add(innerpanel)

        innerpanel.add(subpanel)
        innerpanel.layout = BoxLayout(innerpanel, BoxLayout.Y_AXIS)

        subpanel.border = BorderFactory.createTitledBorder("Redirect Burp Suite connections")
        subpanel.layout = BoxLayout(subpanel, BoxLayout.Y_AXIS)

        subpanel.add(redirect_panel_original)
        subpanel.add(redirect_panel_replacement)
        subpanel.add(redirect_panel_options)
        innerpanel.add(Box.createVerticalGlue())
        innerpanel.add(activationpanel)

        redirect_panel_options.add(dropdown_hostheader)
        redirect_panel_options.add(text_hostheader)
        redirect_panel_options.add(cbox_dns_correction)

        redirect_panel_options.add(do_redirect_scheme_jcheckbox)
        redirect_panel_options.add(do_redirect_transport_jcheckbox)

        text_hostheader.setVisible(false)

        dropdown_hostheader.addActionListener(object: ActionListener {
            override fun actionPerformed(e: ActionEvent) {
                if (!true && e.actionCommand == "") {}  // hack to remove compiler warning about e argument being unused
                dropdown_hostheader_click()
            }
        })

        cbox_dns_correction.setEnabled(false)

        activationpanel.layout = BoxLayout(activationpanel, BoxLayout.X_AXIS)

        activationpanel.add(redirect_button)

        redirect_button.addActionListener(
                object : ActionListener {
                    override fun actionPerformed(e: ActionEvent) {
                        if (!true && e.actionCommand == "") {}  // hack to remove compiler warning about e argument being unused
                        redirect_button_pressed()
                    }
                }
        )

        BurpExtender.cb.customizeUiComponent(mainpanel)
    }

}

/*

****************************************************************************
****************************************************************************
****************************************************************************
****************************************************************************
****************************************************************************
****************************************************************************
****************************************************************************

*/

class BurpExtender : IBurpExtender, IExtensionStateListener {

    companion object {
        lateinit var cb: IBurpExtenderCallbacks
    }


    class Dns_Json() {

        companion object {

            var backup = ""
            var host_list = arrayListOf<String?>()

            fun add(host: String?) {

                var config = cb.saveConfigAsJson(
                    "project_options.connections.hostname_resolution"
                )

                host_list.add(host)

                if (backup == "") {
                    backup = config
                }

                var snippet = "{\"enabled\":true,\"hostname\":\"" +
                                    host +
                                    "\",\"ip_address\":\"127.0.0.1\"}" +
                                    if (config.indexOf("ip_address") >= 0) "," else ""
                config = config.substring(0, 85) + snippet + config.substring(85, config.length)
                cb.loadConfigFromJson(config)
            }

            fun remove(host: String? = "") {

                if (backup != "") {
                    cb.loadConfigFromJson(backup)
                }
                if (host != "") {
                    host_list.remove(host)
                    for (listed_host in host_list) {
                        add(listed_host)
                    }
                }
            }
        }
    }

    override fun extensionUnloaded() {
        Dns_Json.remove()
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {

        cb = callbacks
        val tab = UI()

        cb.setExtensionName("Target Redirector Fork")
        cb.registerExtensionStateListener(this)
        cb.addSuiteTab(tab)
        cb.printOutput("Target Redirector Fork extension loaded")
    }
}
