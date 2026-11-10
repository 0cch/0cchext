# EngExtCpp compatibility sources

This directory contains only the two EngExtCpp source files required when the
Windows Debugging Tools installation is not available (for example, in GitHub
Actions). DbgEng and DbgHelp headers and import libraries are taken from the
installed Windows SDK; no Microsoft SDK headers or libraries are stored here.

Local developers can use the installed Debugging Tools copy with the default
CMake option `0CCHEXT_USE_INSTALLED_ENGEXTCPP=ON`.
