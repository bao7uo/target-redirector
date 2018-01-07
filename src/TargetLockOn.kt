/*

#
#   TargetLockOn Burp extension
#
#   Copyright (C) 2017 Paul Taylor
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

class LockOn {
    companion object {
        var original = ""
        var replacement = ""
        fun update(data_source: UI) {
            original = data_source.text_left.text
            replacement = data_source.text_right.text
            PrintWriter(data_source.callbacks.stdout, true).println("Updated setting. Will replace: ${original} With: ${replacement}")
        }
    }
}

class UI(val callbacks: IBurpExtenderCallbacks) : ITab {

    val mainpanel = JPanel()
    val innerpanel = JPanel()

    val subpanel_upper = JPanel()
    val subpanel_lower = JPanel()

    val button = JButton("Apply settings")

    val textpanel_left = JPanel()
    val label_left = JLabel("Look for:")
    val text_left = JTextField(20)
    val textpanel_right = JPanel()
    val label_right = JLabel("Replace with:")
    val text_right = JTextField(20)

    override val tabCaption = "TargetLockOn"
    override val uiComponent = mainpanel

    fun button_pressed(e: ActionEvent) {
        LockOn.update(this)
    }

    init {
        this.mainpanel.layout = BoxLayout(this.mainpanel, BoxLayout.Y_AXIS)
        this.mainpanel.border = BorderFactory.createEmptyBorder(20, 20, 20, 20)

        this.mainpanel.add(this.innerpanel)
        this.mainpanel.add(Box.createVerticalGlue())

        this.innerpanel.layout = BoxLayout(this.innerpanel, BoxLayout.Y_AXIS)

        this.innerpanel.add(this.subpanel_upper)
        this.innerpanel.add(this.subpanel_lower)

        this.subpanel_upper.border = BorderFactory.createTitledBorder("Replaces matched target hostname/IP in all HTTP requests")

        this.subpanel_upper.add(this.textpanel_left)
        this.subpanel_upper.add(this.textpanel_right)

        this.textpanel_left.add(this.label_left)
        this.textpanel_left.add(this.text_left)

        this.textpanel_right.add(this.label_right)
        this.textpanel_right.add(this.text_right)

        this.subpanel_lower.layout = BoxLayout(this.subpanel_lower, BoxLayout.X_AXIS)

        this.subpanel_lower.add(Box.createHorizontalGlue())
        this.subpanel_lower.add(this.button)

        this.textpanel_left.maximumSize = this.textpanel_left.preferredSize
        this.textpanel_right.maximumSize = this.textpanel_right.preferredSize
        this.subpanel_upper.maximumSize = this.subpanel_upper.preferredSize
        this.subpanel_lower.maximumSize = this.subpanel_lower.preferredSize
        this.innerpanel.maximumSize = this.innerpanel.preferredSize
        this.mainpanel.maximumSize = this.mainpanel.preferredSize

        this.button.addActionListener(
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
            stdout.println("Searching for: ${LockOn.original}")
            stdout.println("Incoming request to: ${messageInfo.httpService.host}")
            if (messageInfo.httpService.host == LockOn.original) {
                messageInfo.httpService = callbacks.helpers.buildHttpService(
                        LockOn.replacement,
                        messageInfo.httpService.port,
                        messageInfo.httpService.protocol
                )
                stdout.println("Target changed from ${LockOn.original} to ${LockOn.replacement}")
            } else {
                stdout.println("Target not changed to ${LockOn.replacement}")
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

        callbacks.setExtensionName("TargetLockOn")

        callbacks.registerHttpListener(httplistener)

        callbacks.customizeUiComponent(tab.mainpanel)
        callbacks.addSuiteTab(tab)

        stdout.println("Loaded")
    }

}
