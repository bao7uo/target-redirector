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

import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.JCheckBox

class Redirector {
    companion object {
        var original_host = ""
        var replacement_host = ""
        var original_port = ""
        var replacement_port = ""
        var original_protocol = ""
        var replacement_protocol = ""

        fun update(data_source: UI) {
            original_host = data_source.text_host_original.text
            replacement_host = data_source.text_host_replacement.text
            original_port = data_source.text_port_original.text
            replacement_port = data_source.text_port_replacement.text
            original_protocol = if (data_source.cbox_https_original.isSelected()) "https" else "http"
            replacement_protocol = if (data_source.cbox_https_replacement.isSelected()) "https" else "http"
            PrintWriter(
                    data_source.callbacks.stdout,
                    true
            ).println(
                    "Redirection Activated. Will replace: ${original_host}:${original_port}/${original_protocol} With: ${replacement_host}:${replacement_port}/${replacement_protocol}"
            )
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
    val cbox_dns_required = JCheckBox("Fix DNS for original host")

    fun button_pressed(e: ActionEvent) {
        Redirector.update(this)
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

        subpanel_upper.border = BorderFactory.createTitledBorder("Redirect ALL connections")
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

        if (messageIsRequest) {
            stdout.println("----->")
            stdout.println("> Searching for: ${Redirector.original_host}:${Redirector.original_port}/${Redirector.original_protocol}")
            stdout.println("> Incoming request to: ${messageInfo.httpService.host}:${messageInfo.httpService.port.toString()}/${messageInfo.httpService.protocol}")
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
                        "> Target changed from ${Redirector.original_host}:${Redirector.original_port}/${Redirector.original_protocol} to ${Redirector.replacement_host}:${Redirector.replacement_port}/${Redirector.replacement_protocol}"
                )
            } else {
                stdout.println("> Target not changed to ${Redirector.replacement_host}:${Redirector.replacement_port}/${Redirector.replacement_protocol}")
            }
        } else {
            stdout.println("<-----")
            stdout.println("< Incoming response from: ${messageInfo.httpService.host}:${messageInfo.httpService.port.toString()}/${messageInfo.httpService.protocol}")
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
