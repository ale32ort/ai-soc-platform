from tools.providers.anthropic_provider import AnthropicProvider


context = """
Windows Event 7045

A new Windows service was installed.

Service Name:
UpdaterService

Executable:
C:\\Users\\Public\\updater.exe

User:
Administrator

Host:
tito

Related Events:
4688 Process Creation
4624 Successful Logon

Timeline:
09:15 Service Installed
09:15 updater.exe executed
09:16 outbound network connection observed
"""

provider = AnthropicProvider()

result = provider.investigate(context)

print(result.pretty_print())
