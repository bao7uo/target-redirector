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


class HttpListener(val cb: IBurpExtenderCallbacks, val redirector: Redirector) : IHttpListener {

    override fun processHttpMessage(
            toolFlag: Int,
            messageIsRequest: Boolean,
            messageInfo: IHttpRequestResponse
    ) {
        redirector.process_redirect(messageIsRequest, messageInfo)
    }
}


class Redirector(val cb: IBurpExtenderCallbacks) {

    var listener = HttpListener(cb, this)

    var active = false
        
    lateinit var original: Map<String, String>
    lateinit var replacement: Map<String, String>

    var json_backup = ""

    fun original_url() = "${original["protocol"]}://${original["host"]}:${original["port"]}"
    fun replacement_url() = "${replacement["protocol"]}://${replacement["host"]}:${replacement["port"]}"

    fun process_redirect(messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        val current = "${messageInfo.httpService.protocol}://${messageInfo.httpService.host}:${messageInfo.httpService.port.toString()}"

        if (!active) {return}

        if (messageIsRequest) {
            cb.printOutput("----->")
            cb.printOutput("> Searching for: ${original_url()}")
            cb.printOutput("> Incoming request to: ${current}")
            if (messageInfo.httpService.host == original["host"]
                    && messageInfo.httpService.port == original["port"]?.toIntOrNull()
                    && (messageInfo.httpService.protocol == original["protocol"])
                    ) {
                messageInfo.httpService = cb.helpers.buildHttpService(
                        replacement["host"],
                        replacement["port"]!!.toInt(),
                        replacement["protocol"]
                )
                cb.printOutput(
                        "> Target changed from ${original_url()} to ${replacement_url()}"
                )
            } else {
                cb.printOutput("> Target not changed to ${replacement_url()}")
            }
        } else {
            cb.printOutput("<-----")
            cb.printOutput("< Incoming response from: ${current}")
        }        
    }

    fun toggle(data_source: UI, mainpanel: JPanel, original_data: Map<String, String>, replacement_data: Map<String, String>) {
        if (active) {
            stop(data_source)
        } else  update(data_source, mainpanel, original_data, replacement_data)
    }

    fun stop(data_source: UI) {

        cb.removeHttpListener(listener)
        active = false
        data_source.toggle_active(false)

        if (json_backup != "") {
            cb.loadConfigFromJson(json_backup)
            json_backup = ""
        }
    }

    fun update(data_source: UI, mainpanel: JPanel, original_data: Map<String, String>, replacement_data: Map<String, String>) {

        original = original_data
        replacement = replacement_data

        fun getbyname(name: String): Boolean {
            try {
                InetAddress.getByName(name)
                return true
            }
            catch (UnknownHostException: Exception) {
                cb.printOutput("Hostname/IP \"${name}\" appears to be invalid.")
                return false
            }
        }

        fun notification(text: String) {
            JOptionPane.showMessageDialog(mainpanel, text, "Burp / Target Redirector", JOptionPane.WARNING_MESSAGE)
            cb.printOutput(text) 
        }

        if (
            !original["host"].isNullOrBlank() &&
            original["port"]?.toIntOrNull() != null &&
            !replacement["host"].isNullOrBlank() &&
            replacement["port"]?.toIntOrNull() != null &&
            getbyname(replacement["host"]!!)
            ) {
                if (!getbyname(original["host"]!!)) {
                    notification("Original hostname \"${original["host"]}\" appears to be invalid.\n\n" +
                        "Target Redirector will add an entry to\nProject options / Hostname Resolution\n" +
                        "to allow Burp to send requests with an\n" +
                        "invalid hostname via this extension.")

                    var json_config = cb.saveConfigAsJson(
                        "project_options.connections.hostname_resolution"
                    )

                    json_backup = json_config

                    var json_snippet = "{\"enabled\":true,\"hostname\":\"" +
                                        original["host"] +
                                        "\",\"ip_address\":\"127.0.0.1\"}" +
                                        if (json_config.indexOf("ip_address") >= 0) "," else ""
                    json_config = json_config.substring(0, 85) + json_snippet + json_config.substring(85, json_config.length)
                    cb.loadConfigFromJson(json_config)

                    data_source.toggle_dns_correction(true)
                } else {
                    data_source.toggle_dns_correction(false)
                }

                notification(
                    "Redirection Activated.\nTarget Redirector is now\nredirecting requests for:\n${original_url()}\nto:\n${replacement_url()}"
                )

                cb.registerHttpListener(listener)
                active = true
                data_source.toggle_active(true)
        } else {
                notification("Invalid hostname and/or port settings.")
        }
    }
}


class UI(val cb: IBurpExtenderCallbacks, val redirector: Redirector) : ITab {

    override public fun getTabCaption() = "Target Redirector"
    override public fun getUiComponent() = mainpanel

    val mainpanel = JPanel()
    val innerpanel = JPanel()

    val subpanel_upper = JPanel()
    val subpanel_lower = JPanel()

    class redirect_panel(val host: String) : JPanel() {

        val label_host = JLabel(host)       
        val text_host = JTextField(20)

        val label_port = JLabel("on port")
        val text_port = JTextField(5)

        val cbox_https = JCheckBox("with HTTPS")  

        init {
            add(label_host)
            add(text_host)
            add(label_port)
            add(text_port)
            add(cbox_https)
            maximumSize = preferredSize
        }

        fun get_data(): Map<String, String> {
            val data = mutableMapOf<String, String>()
            data["host"] = text_host.text
            data["port"] = text_port.text
            data["protocol"] = if (cbox_https.isSelected()) "https" else "http"
            return data
        }

        fun toggle_lock(locked: Boolean) {
            text_host.setEditable(locked)
            text_port.setEditable(locked)
            cbox_https.setEnabled(locked)
        }
    }

    val redirect_panel_original = redirect_panel("for host/IP")
    val redirect_panel_replacement = redirect_panel("to: host/IP")

    fun toggle_active(active: Boolean) {
        button.text = if (active) "Remove redirection" else "Activate redirection"
        redirect_panel_original.toggle_lock(!active)
        redirect_panel_replacement.toggle_lock(!active)
        if (!active) { cbox_dns_correction.setSelected(false) }
    }

    fun toggle_dns_correction(enabled: Boolean) {
        cbox_dns_correction.setSelected(enabled)
    }

    val redirect_panel_options = JPanel()
    val cbox_hostheader = JCheckBox("Also replace HTTP host header")
    val cbox_dns_correction = JCheckBox("Invalid original hostname DNS correction")

    val button = JButton("Activate Redirection")

    fun button_pressed() {
        redirector.toggle(this, mainpanel, redirect_panel_original.get_data(), redirect_panel_replacement.get_data())
    }
    
    init {
        mainpanel.layout = BoxLayout(mainpanel, BoxLayout.Y_AXIS)
        mainpanel.border = BorderFactory.createEmptyBorder(20, 20, 20, 20)

        mainpanel.add(innerpanel)
        mainpanel.add(Box.createVerticalGlue())

        innerpanel.layout = BoxLayout(innerpanel, BoxLayout.Y_AXIS)

        innerpanel.add(subpanel_upper)
        innerpanel.add(subpanel_lower)

        subpanel_upper.border = BorderFactory.createTitledBorder("Redirect all Burp connections")
        subpanel_upper.layout = BoxLayout(subpanel_upper, BoxLayout.Y_AXIS)

        subpanel_upper.add(redirect_panel_original)
        subpanel_upper.add(redirect_panel_replacement)
        subpanel_upper.add(redirect_panel_options)

        redirect_panel_options.add(cbox_hostheader)
        redirect_panel_options.add(cbox_dns_correction)

        cbox_hostheader.setEnabled(false)
        cbox_dns_correction.setEnabled(false)

        subpanel_lower.layout = BoxLayout(subpanel_lower, BoxLayout.X_AXIS)

        subpanel_lower.add(Box.createHorizontalGlue())
        subpanel_lower.add(button)
        subpanel_lower.add(Box.createVerticalGlue())

        subpanel_upper.maximumSize = subpanel_upper.preferredSize
        subpanel_lower.maximumSize = subpanel_lower.preferredSize
        innerpanel.maximumSize = innerpanel.preferredSize
        mainpanel.maximumSize = mainpanel.preferredSize

        button.addActionListener(
                object : ActionListener {
                    override fun actionPerformed(e: ActionEvent) {
                        if (!true && e.actionCommand == "") {}  // hack to remove compiler warning
                        button_pressed()                        // about e argument being unused
                    }
                }
        )

        cb.customizeUiComponent(mainpanel)
    }

}

class BurpExtender : IBurpExtender {

    override fun registerExtenderCallbacks(cb: IBurpExtenderCallbacks) {       
        
        val tab = UI(cb, Redirector(cb))

        cb.setExtensionName("Target Redirector")
        cb.addSuiteTab(tab)
        cb.printOutput("Target Redirector extension loaded")
    }

}
