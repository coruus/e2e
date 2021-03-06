// Copyright 2013 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
/**
 * @fileoverview A generic dialog that can be used to prompt the user for small
 * bits of additional information.
 */

goog.provide('e2e.ext.ui.Dialog');

goog.require('e2e.ext.constants');
goog.require('e2e.ext.ui.templates');
goog.require('goog.dom');
goog.require('goog.dom.TagName');
goog.require('goog.dom.classes');
goog.require('goog.events.KeyCodes');
goog.require('goog.ui.Component');
goog.require('goog.ui.KeyboardShortcutHandler');
goog.require('goog.ui.KeyboardShortcutHandler.EventType');
goog.require('soy');


goog.scope(function() {
var ui = e2e.ext.ui;
var constants = e2e.ext.constants;
var templates = e2e.ext.ui.templates;



/**
 * Constructor for the dialog.
 * @param {string|soydata.SanitizedHtml} message The message to display to
 *     the user.
 * @param {!function(string=)} callback The callback where the user's
 *     input must be passed.
 * @param {ui.Dialog.InputType} inputType The type of input the dialog should
 *     ask for. If TEXT, a text field will be provided. If SECURE_TEXT, a
 *     password field will be provided. Defaults to NONE.
 * @param {string=} opt_placeholder Optional. A message to display as a
 *     placeholder in the dialog's input box. Defaults to an empty string.
 * @param {string=} opt_actionButtonTitle Optional. The title for the action
 *     button. Defaults to "OK".
 * @param {string=} opt_cancelButtonTitle Optional. The title for the cancel
 *     button. Defaults to "Cancel".
 * @constructor
 * @extends {goog.ui.Component}
 */
ui.Dialog = function(message, callback, inputType, opt_placeholder,
    opt_actionButtonTitle, opt_cancelButtonTitle) {
  goog.base(this);

  /**
   * The message to display to the user.
   * @type {string|soydata.SanitizedHtml}
   * @private
   */
  this.message_ = message;

  /**
   * The callback to invoke once the user has provided input.
   * @type {!function(string=)}
   * @private
   */
  this.dialogCallback_ = callback;

  /**
   * The type of input the dialog should ask for. If TEXT, a text field will be
   * provided. If SECURE_TEXT, a password field will be provided. Defaults to
   * NONE.
   * @type {ui.Dialog.InputType}
   * @private
   */
  this.inputType_ = inputType;

  /**
   * A message to display as a placeholder in the dialog's input box.
   * @type {string}
   * @private
   */
  this.placeholder_ = opt_placeholder || '';

  /**
   * The title for the dialog's action button.
   * @type {string}
   * @private
   */
  this.actionButtonTitle_ = opt_actionButtonTitle || 'OK';

  /**
   * The title for the dialog's cancel button.
   * @type {string}
   * @private
   */
  this.cancelButtonTitle_ = opt_cancelButtonTitle || '';
};
goog.inherits(ui.Dialog, goog.ui.Component);


/**
 * The type of input the dialog should handle.
 * @enum {string}
 */
ui.Dialog.InputType = {
  NONE: '',
  TEXT: 'text',
  SECURE_TEXT: 'password'
};


/**
 * The dialog's input field.
 * @type {Element}
 * @private
 */
ui.Dialog.prototype.inputElem_ = null;


/**
 * A keyboard shortcut handler.
 * @type {goog.ui.KeyboardShortcutHandler}
 * @private
 */
ui.Dialog.prototype.keyboardHandler_ = null;


/** @override */
ui.Dialog.prototype.createDom = function() {
  this.decorateInternal(goog.dom.createElement(goog.dom.TagName.DIV));
};


/** @override */
ui.Dialog.prototype.decorateInternal = function(elem) {
  this.setElementInternal(elem);

  soy.renderElement(elem, templates.Dialog, {
    message: this.message_,
    inputFieldType: this.inputType_,
    inputPlaceholder: this.placeholder_,
    actionButtonTitle: this.actionButtonTitle_,
    cancelButtonTitle: this.cancelButtonTitle_
  });

  this.inputElem_ = this.getElementByClass(constants.CssClass.DIALOG_INPUT);
};


/** @override */
ui.Dialog.prototype.enterDocument = function() {
  goog.base(this, 'enterDocument');

  var body = goog.dom.getElement(constants.ElementId.BODY);
  if (body) {
    goog.dom.classes.add(body, constants.CssClass.TRANSPARENT);
  }

  var elem = this.getElement();
  var position = goog.style.getPosition(elem);
  var parentElem = this.getParent().getElement();
  if (goog.style.getSize(parentElem) > goog.style.getSize(elem)) {
    position.y = goog.style.getSize(this.getParent().getElement()).height / 2 -
        goog.style.getSize(elem).height / 2;
  } else {
    position.y = 0;
  }
  goog.style.setPosition(elem, position);

  if (this.inputElem_) {
    // Autofocus works only on one element in a document, so we focus().
    this.inputElem_.focus();
    this.keyboardHandler_ =
        new goog.ui.KeyboardShortcutHandler(this.inputElem_);
    this.keyboardHandler_.registerShortcut('enter', goog.events.KeyCodes.ENTER);
    this.getHandler().listenOnce(
        this.keyboardHandler_,
        goog.ui.KeyboardShortcutHandler.EventType.SHORTCUT_TRIGGERED,
        goog.partial(this.invokeCallback_, false));
  }

  this.getHandler().listen(
      this.getElementByClass(constants.CssClass.ACTION),
      goog.events.EventType.CLICK,
      goog.partial(this.invokeCallback_, false));

  if (this.cancelButtonTitle_) {
    this.getHandler().listen(
        this.getElementByClass(constants.CssClass.CANCEL),
        goog.events.EventType.CLICK,
        goog.partial(this.invokeCallback_, true));
  }
};


/** @override */
ui.Dialog.prototype.exitDocument = function() {
  var body = goog.dom.getElement(constants.ElementId.BODY);
  if (body) {
    goog.dom.classes.remove(body, constants.CssClass.TRANSPARENT);
  }

  goog.base(this, 'exitDocument');
};


/**
 * Restores the UI prior to the display of the dialog and invokes the callback.
 * @param {boolean} sendBlank If true, the callback will be called with an empty
 *     value.
 * @private
 */
ui.Dialog.prototype.invokeCallback_ = function(sendBlank) {
  if (this.inputElem_) {
    var returnValue = sendBlank ? '' : this.inputElem_.value;
    this.inputElem_.value = '';
    this.dialogCallback_(returnValue);
  } else {
    this.dialogCallback_(sendBlank ? undefined : '');
  }
};


}); // goog.scope

