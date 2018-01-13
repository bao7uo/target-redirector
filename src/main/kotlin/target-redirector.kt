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

import java.io.PrintWriter

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


class Redirector {

    companion object {
        var original_host = ""
        var replacement_host = ""
        var original_port = ""
        var replacement_port = ""
        var original_protocol = ""
        var replacement_protocol = ""

        var json_backup = ""

        fun original() = "${original_protocol}://${original_host}:${original_port}"
        fun replacement() = "${replacement_protocol}://${replacement_host}:${replacement_port}"

        fun stop(data_source: UI) {
            data_source.button.text = "Activate redirection"
            original_port = "ZZZZ"
            replacement_port = "ZZZZ"
            data_source.cbox_dns_required.setSelected(false)
            if (json_backup != "") {
                data_source.callbacks.loadConfigFromJson(json_backup)
                json_backup = ""
            }
        }

        fun update(data_source: UI) {

            var stdout = PrintWriter(
                                data_source.callbacks.stdout,
                                true
                            )

            val _original_host = data_source.text_host_original.text
            val _replacement_host = data_source.text_host_replacement.text
            val _original_port = data_source.text_port_original.text
            val _replacement_port = data_source.text_port_replacement.text
            val _original_protocol = if (data_source.cbox_https_original.isSelected()) "https" else "http"
            val _replacement_protocol = if (data_source.cbox_https_replacement.isSelected()) "https" else "http"

            fun getbyname(name: String): Boolean {
                try {
                    InetAddress.getByName(name)
                    return true
                }
                catch (UnknownHostException: Exception) {
                    stdout.println("Hostname/IP \"${name}\" appears to be invalid.")
                    return false
                }
            }

            fun notification(text: String) {
                JOptionPane.showMessageDialog(data_source.mainpanel, text, "Burp / Target Redirector", JOptionPane.WARNING_MESSAGE)
                stdout.println(text) 
            }

            if (
                _original_host != "" &&
                _original_port.toIntOrNull() != null &&
                _replacement_host != "" &&
                _replacement_port.toIntOrNull() != null &&
                getbyname(_replacement_host)
                ) {
                    if (!getbyname(_original_host)) {
                        notification("Original hostname \"${_original_host}\" appears to be invalid.\n\n" +
                            "Target Redirector will add an entry to\nProject options / Hostname Resolution\n" +
                            "to allow Burp to send requests with an\n" +
                            "invalid hostname via this extension.")

                        var json_config = data_source.callbacks.saveConfigAsJson(
                            "project_options.connections.hostname_resolution"
                        )

                        json_backup = json_config

                        var json_snippet = "{\"enabled\":true,\"hostname\":\"" +
                                            _original_host +
                                            "\",\"ip_address\":\"127.0.0.1\"}" +
                                            if (json_config.indexOf("ip_address") >= 0) "," else ""
                        json_config = json_config.substring(0, 89) + json_snippet + json_config.substring(89, json_config.length)
                        data_source.callbacks.loadConfigFromJson(json_config)

                        data_source.cbox_dns_required.setSelected(true)
                    } else {
                        data_source.cbox_dns_required.setSelected(false)
                    }

                    original_host = _original_host
                    replacement_host = _replacement_host
                    original_port = _original_port
                    replacement_port = _replacement_port
                    original_protocol = _original_protocol
                    replacement_protocol = _replacement_protocol

                    notification(
                        "Redirection Activated.\nTarget Redirector is now\nredirecting requests for:\n${original()}\nto:\n${replacement()}"
                    )

                    data_source.button.text = "Remove redirection"
            } else {
                    notification("Invalid hostname and/or port settings.")
            }
        }
    }
}


class UI(val callbacks: IBurpExtenderCallbacks) : ITab {

    val mainpanel = JPanel()
    val innerpanel = JPanel()

    val subpanel_upper = JPanel()
    val subpanel_lower = JPanel()

    val button = JButton("Activate Redirection")

    val textpanel_original = JPanel()
    val label_host_original = JLabel("for host/IP")
    val text_host_original = JTextField(20)
    val label_port_original = JLabel("on port")
    val text_port_original = JTextField(5)

    val cbox_https_original = JCheckBox("with HTTPS")

    val textpanel_replacement = JPanel()
    val label_host_replacement = JLabel("to: host/IP")
    val text_host_replacement = JTextField(20)
    val label_port_replacement = JLabel("on port")
    val text_port_replacement = JTextField(5)

    val cbox_https_replacement = JCheckBox("with HTTPS")

    val textpanel_options = JPanel()

    val cbox_hostheader = JCheckBox("Also replace HTTP host header")
    val cbox_dns_required = JCheckBox("Invalid original hostname DNS correction")

    fun button_pressed(e: ActionEvent) {
        if (button.text != "Remove redirection") Redirector.update(this)
        else Redirector.stop(this)
    }
    
    override public fun getTabCaption() = "Target Redirector"

    override public fun getUiComponent() = mainpanel

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

        subpanel_upper.add(textpanel_original)
        subpanel_upper.add(textpanel_replacement)
        subpanel_upper.add(textpanel_options)

        textpanel_original.add(label_host_original)
        textpanel_original.add(text_host_original)
        textpanel_original.add(label_port_original)
        textpanel_original.add(text_port_original)
        textpanel_original.add(cbox_https_original)

        textpanel_replacement.add(label_host_replacement)
        textpanel_replacement.add(text_host_replacement)
        textpanel_replacement.add(label_port_replacement)
        textpanel_replacement.add(text_port_replacement)
        textpanel_replacement.add(cbox_https_replacement)

        textpanel_options.add(cbox_hostheader)
        textpanel_options.add(cbox_dns_required)

        cbox_hostheader.setEnabled(false)
        cbox_dns_required.setEnabled(false)

        subpanel_lower.layout = BoxLayout(subpanel_lower, BoxLayout.X_AXIS)

        subpanel_lower.add(Box.createHorizontalGlue())
        subpanel_lower.add(button)
        subpanel_lower.add(Box.createVerticalGlue())

        textpanel_original.maximumSize = textpanel_original.preferredSize
        textpanel_replacement.maximumSize = textpanel_replacement.preferredSize
        subpanel_upper.maximumSize = subpanel_upper.preferredSize
        subpanel_lower.maximumSize = subpanel_lower.preferredSize
        innerpanel.maximumSize = innerpanel.preferredSize
        mainpanel.maximumSize = mainpanel.preferredSize

        button.addActionListener(
                object : ActionListener {
                    override fun actionPerformed(e: ActionEvent) {
                        button_pressed(e)
                    }
                }
        )
    }

}

class HttpListener(val callbacks: IBurpExtenderCallbacks) : IHttpListener {

    override fun processHttpMessage(
            toolFlag: Int,
            messageIsRequest: Boolean,
            messageInfo: IHttpRequestResponse
    ) {
        var stdout = PrintWriter(callbacks.stdout, true)
        val current = "${messageInfo.httpService.protocol}://${messageInfo.httpService.host}:${messageInfo.httpService.port.toString()}"

        if (messageIsRequest) {
            stdout.println("----->")
            stdout.println("> Searching for: ${Redirector.original()}")
            stdout.println("> Incoming request to: ${current}")
            if (messageInfo.httpService.host == Redirector.original_host
                    && messageInfo.httpService.port == Redirector.original_port.toIntOrNull()
                    && (messageInfo.httpService.protocol == Redirector.original_protocol)
                    ) {
                messageInfo.httpService = callbacks.helpers.buildHttpService(
                        Redirector.replacement_host,
                        Redirector.replacement_port.toInt(),
                        Redirector.replacement_protocol
                )
                stdout.println(
                        "> Target changed from ${Redirector.original()} to ${Redirector.replacement()}"
                )
            } else {
                stdout.println("> Target not changed to ${Redirector.replacement()}")
            }
        } else {
            stdout.println("<-----")
            stdout.println("< Incoming response from: ${current}")
        }
    }
}


class BurpExtender : IBurpExtender {

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {

        var stdout = PrintWriter(callbacks.stdout, true)

        val httplistener = HttpListener(callbacks)
        val tab = UI(callbacks)

        callbacks.setExtensionName("Target Redirector")

        callbacks.registerHttpListener(httplistener)

        callbacks.customizeUiComponent(tab.mainpanel)
        callbacks.addSuiteTab(tab)

        stdout.println("Target Redirector extension loaded")
    }

}
