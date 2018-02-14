/*

#
#   Target Redirector Burp extension
#
#   Copyright (C) 2016-2018 Paul Taylor
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
import javax.swing.JOptionPane


class Redirector(val id: Int, val view: UI, val host_header: Boolean, val original: Map<String, String?>, val replacement: Map<String, String?>) {

    companion object {

        var instances = mutableListOf<Redirector>()
        lateinit var view: UI

        fun notification(message: String) {
            view.notification(message, "Redirector")
        }

        fun add_instance(host_header: Boolean, original_data: Map<String, String?>, replacement_data: Map<String, String?>) {
            val id = instances.size
            instances.add(Redirector(id, view, host_header, original_data, replacement_data))
            notification("Initialising new redirector #" + id + " (total " + instances.size + ")")
        }

        fun remove_instance(id: Int) {
            instances.removeAt(id)
            notification("Removed redirector #" + id + " (new total " + instances.size + ")")
        }

        fun instance_add_or_remove(view_arg: UI, host_header: Boolean, original_data: Map<String, String?>, replacement_data: Map<String, String?>) : Int {

            view = view_arg

            if (instances.isEmpty()) {
                add_instance(host_header, original_data, replacement_data)
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

    var header_hostname = replacement["host"]
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

    fun original_url() = "${original["protocol"]}://${original["host"]}:${original["port"]}"
    fun replacement_url() = "${replacement["protocol"]}://${replacement["host"]}:${replacement["port"]}"

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

    fun toggle_dns_correction() {

        if (active) {
            if (original["host_regex"] == "0") BurpExtender.Dns_Json.remove(original["host"])
            return
        } else if (original["host_regex"] == "0" && !getbyname(original["host"], false)) {
            notification("Hostname/IP \"${original["host"]}\" appears to be invalid.\n\n" +
                "An entry will be added to\nProject options / Hostname Resolution\n" +
                "to allow invalid hostname redirection.", true)

            BurpExtender.Dns_Json.add(original["host"])

            view.toggle_dns_correction(true)
        } else {
            view.toggle_dns_correction(false)
        }        
    }

    fun activate(): Boolean {

        if (
            !original["host"].isNullOrBlank() &&
            !original["port"].isNullOrBlank() &&
            (original["port"]?.toIntOrNull() != null || original["port_regex"] == "1") &&
            !replacement["host"].isNullOrBlank() &&
            replacement["port"]?.toIntOrNull() != null &&
            getbyname(replacement["host"], true, true)
            ) {
                toggle_dns_correction()
                if (host_header) {
                    var fetch_result = fetch_input(
                                "Enter the value to replace HTTP host header with",
                                replacement["host"]
                            )
                    header_hostname = if (fetch_result.isEmpty()) replacement["host"] else fetch_result
                    notification(
                        "Replacing HTTP host header with: " + header_hostname!!,
                        if (fetch_result.isEmpty()) true else false
                    )
                }
                return true
        } else {
                return false
        }
    }

    fun host_header_set(messageInfo: IHttpRequestResponse){

        val host_regex ="^(?i)(Host:)( {0,1})(.*)$".toRegex(RegexOption.IGNORE_CASE)

        var old_header_set = false
        var old_host: String?
        var new_host = header_hostname
        var new_header = "Host: " + new_host

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
                    if (old_host == new_host) {
                        notification("Old host header is already set to ${new_host}, no change required")
                        return
                    } else {
                        notification("> Host header changed from ${old_host} to ${new_host}")
                        new_headers.add(new_header)
                        old_header_set = true
                    }
                }
            }
        }

        if (!old_header_set) {
            notification("> Existing host header not found. New host header set to ${new_host}")
            new_headers.add(1, new_header)
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
               (
                if (original["host_regex"] == "0") (messageInfo.httpService.host.toLowerCase() == original["host"])
                else original["host"]?.toRegex(RegexOption.IGNORE_CASE)?.matches(messageInfo.httpService.host)!!
            )
            && (
                if (original["port_regex"] == "0") (messageInfo.httpService.port == original["port"]?.toInt())
                else original["port"]?.toRegex(RegexOption.IGNORE_CASE)?.matches(messageInfo.httpService.port.toString())!!
            )
            && (
                messageInfo.httpService.protocol == original["protocol"]
            )
        ) {

            notification(
                "> Target changed from ${messageInfo.httpService.protocol}://${messageInfo.httpService.host}:${messageInfo.httpService.port.toString()} to ${replacement_url()}"
            )
            
            messageInfo.httpService = BurpExtender.cb.helpers.buildHttpService(
                replacement["host"],
                replacement["port"]!!.toInt(),
                replacement["protocol"]
            )

            if (host_header) {
                host_header_set(messageInfo)
            }
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


class UI() : ITab {

    override public fun getTabCaption() = "Target Redirector"
    override public fun getUiComponent() = mainpanel

    val mainpanel = JPanel()
    val innerpanel = JPanel()

    val subpanel_upper = JPanel()
    val subpanel_lower = JPanel()

    class redirect_panel(val host: String, val regex: Boolean) : JPanel() {

        val label_host = JLabel(host)       
        val text_host = JTextField(20)

        val label_port = JLabel("on port")
        val text_port = JTextField(5)

        val cbox_https = JCheckBox("with HTTPS" + if (regex) "     Regex:" else "")  
       
        val cbox_host_regex = JCheckBox("host")
        val cbox_port_regex = JCheckBox("port")

        init {
            add(label_host)
            add(text_host)
            add(label_port)
            add(text_port)
            add(cbox_https)

            if (regex) {
                add(cbox_host_regex)
                add(cbox_port_regex)
            } else {
                // add()
            }
        }

        fun get_data(): Map<String, String> {
            val data = mutableMapOf<String, String>()
            if (!cbox_host_regex.isSelected()) text_host.text = text_host.text.toLowerCase()
            data["host"] = text_host.text
            data["port"] = text_port.text
            data["protocol"] = if (cbox_https.isSelected()) "https" else "http"
            if (regex) {
                data["host_regex"] = if (cbox_host_regex.isSelected()) "1" else "0"
                data["port_regex"] = if (cbox_port_regex.isSelected()) "1" else "0"
            }
            return data
        }

        fun toggle_lock(locked: Boolean) {
            text_host.setEditable(locked)
            text_port.setEditable(locked)
            cbox_https.setEnabled(locked)
            cbox_host_regex.setEnabled(locked)
            cbox_port_regex.setEnabled(locked)
        }
    }

    val redirect_panel_original = redirect_panel("for host/IP", true)
    val redirect_panel_replacement = redirect_panel("to: host/IP", false)

    fun toggle_active(active: Boolean) {
        redirect_button.text = if (active) "Remove redirection" else "Activate redirection"
        redirect_panel_original.toggle_lock(active.not())
        redirect_panel_replacement.toggle_lock(active.not())
        cbox_hostheader.setEnabled(active.not())
        if (!active) { cbox_dns_correction.setSelected(false) }
    }

    fun toggle_dns_correction(enabled: Boolean) {
        cbox_dns_correction.setSelected(enabled)
    }

    val redirect_panel_options = JPanel()
    val cbox_hostheader = JCheckBox("Also replace HTTP host header")
    val cbox_dns_correction = JCheckBox("Invalid original hostname DNS correction")

    val redirect_button = JButton("Activate Redirection")

    fun redirect_button_pressed() {

        val instance_id = Redirector.instance_add_or_remove(
                this,
                cbox_hostheader.isSelected(),
                redirect_panel_original.get_data(),
                redirect_panel_replacement.get_data()
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

    init {

        mainpanel.layout = BoxLayout(mainpanel, BoxLayout.Y_AXIS)
        mainpanel.border = BorderFactory.createEmptyBorder(20, 20, 20, 20)

        mainpanel.add(innerpanel)
        mainpanel.add(Box.createVerticalGlue())

        innerpanel.layout = BoxLayout(innerpanel, BoxLayout.Y_AXIS)

        innerpanel.add(subpanel_upper)
        innerpanel.add(subpanel_lower)

        subpanel_upper.border = BorderFactory.createTitledBorder("Redirect all Burp Suite connections")
        subpanel_upper.layout = BoxLayout(subpanel_upper, BoxLayout.Y_AXIS)

        subpanel_upper.add(redirect_panel_original)
        subpanel_upper.add(redirect_panel_replacement)
        subpanel_upper.add(redirect_panel_options)

        redirect_panel_options.add(cbox_hostheader)
        redirect_panel_options.add(cbox_dns_correction)

        cbox_hostheader.setEnabled(true)
        cbox_dns_correction.setEnabled(false)

        subpanel_lower.layout = BoxLayout(subpanel_lower, BoxLayout.X_AXIS)

        subpanel_lower.add(Box.createHorizontalGlue())
        subpanel_lower.add(redirect_button)
        subpanel_lower.add(Box.createVerticalGlue())

        subpanel_upper.maximumSize = subpanel_upper.preferredSize
        subpanel_lower.maximumSize = subpanel_lower.preferredSize
        innerpanel.maximumSize = innerpanel.preferredSize
        mainpanel.maximumSize = mainpanel.preferredSize

        redirect_button.addActionListener(
                object : ActionListener {
                    override fun actionPerformed(e: ActionEvent) {
                        if (!true && e.actionCommand == "") {}  // hack to remove compiler warning
                        redirect_button_pressed()                        // about e argument being unused
                    }
                }
        )

        BurpExtender.cb.customizeUiComponent(mainpanel)
    }

}


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
        
        cb.setExtensionName("Target Redirector")
        cb.registerExtensionStateListener(this)
        cb.addSuiteTab(tab)
        cb.printOutput("Target Redirector extension loaded")
    }
}
