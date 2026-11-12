'use strict';

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ESCAPES[character]);
}

function renderTemplate(template, context) {
  return template.replace(/\{\{(\w+)\}\}/g, (_, name) => escapeHtml(context[name] ?? ''));
}

function renderStatementRow(row) {
  return renderTemplate('<tr><td>{{date}}</td><td>{{narration}}</td><td>{{amount}}</td></tr>', row);
}

function renderGreeting(req, res) {
  res.send('<h1>Welcome back, ' + req.query.name + '</h1>');
}

function renderGreetingSafely(req, res) {
  res.send('<h1>Welcome back, ' + escapeHtml(req.query.name) + '</h1>');
}

module.exports = { escapeHtml, renderTemplate, renderStatementRow, renderGreeting, renderGreetingSafely };
