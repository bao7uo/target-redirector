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
import javax.swing.JComponent

class Redirector {
    companion object {
        var original = ""
        var replacement = ""
        fun update(data_source: UI) {
            original = data_source.text_left.text
            replacement = data_source.text_right.text
            PrintWriter(data_source.callbacks.stdout, true).println("Redirection Activated. Will replace: ${original} With: ${replacement}")
        }
    }
}

class UI(val callbacks: IBurpExtenderCallbacks) : ITab {

    val mainpanel = JPanel()
    val innerpanel = JPanel()

    val subpanel_upper = JPanel()
    val subpanel_lower = JPanel()

    val button = JButton("Activate Redirection")

    val textpanel_left = JPanel()
    val label_left = JLabel("Look for:")
    val text_left = JTextField(20)
    val textpanel_right = JPanel()
    val label_right = JLabel("Replace with:")
    val text_right = JTextField(20)

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

        subpanel_upper.border = BorderFactory.createTitledBorder("Replaces matched target hostname/IP in all HTTP requests")

        subpanel_upper.add(textpanel_left)
        subpanel_upper.add(textpanel_right)

        textpanel_left.add(label_left)
        textpanel_left.add(text_left)

        textpanel_right.add(label_right)
        textpanel_right.add(text_right)

        subpanel_lower.layout = BoxLayout(subpanel_lower, BoxLayout.X_AXIS)

        subpanel_lower.add(Box.createHorizontalGlue())
        subpanel_lower.add(button)

        textpanel_left.maximumSize = textpanel_left.preferredSize
        textpanel_right.maximumSize = textpanel_right.preferredSize
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
            stdout.println("Searching for: ${Redirector.original}")
            stdout.println("Incoming request to: ${messageInfo.httpService.host}")
            if (messageInfo.httpService.host == Redirector.original) {
                messageInfo.httpService = callbacks.helpers.buildHttpService(
                        Redirector.replacement,
                        messageInfo.httpService.port,
                        messageInfo.httpService.protocol
                )
                stdout.println("Target changed from ${Redirector.original} to ${Redirector.replacement}")
            } else {
                stdout.println("Target not changed to ${Redirector.replacement}")
            }
        } else {
            stdout.println("Incoming response from: ${messageInfo.httpService.host}")
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

        stdout.println("Extension Loaded")
    }

}
