# Get the path to the current user's Desktop
$desktopPath = [Environment]::GetFolderPath("SpecialFolder")::Desktop
# Note: Alternatively, you can use $HOME\Desktop

# Define the file path and content
$filePath = "$HOME\Desktop\temp.txt"
$fileContent = "This is a temporary text file created by a PowerShell script."

# Create and save the text file
Set-Content -Path $filePath -Value $fileContent

Write-Host "Temp text file successfully saved to your desktop!" -ForegroundColor Green