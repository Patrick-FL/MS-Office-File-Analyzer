; This script was created using Pulover's Macro Creator
; www.macrocreator.com

#NoEnv
SetWorkingDir %A_ScriptDir%
CoordMode, Mouse, Window
SendMode Input
#SingleInstance Force
SetTitleMatchMode 2
#WinActivateForce
SetControlDelay 1
SetWinDelay 0
SetKeyDelay -1
SetMouseDelay -1
SetBatchLines -1


MSOAnalyzer:
Progress, b w200, MS Office File Analyzer, Please wait until the files have been analyzed.,   ; Create a Progress Bar
/*
Create work directory to put MS Office files in folder. 
*/
Startverzeichnis := A_ScriptDir "\Working Folder\"
IfNotExist, %Startverzeichnis%
{
    MsgBox, 0, Guidance, 
    (LTrim
    Put the MS Office files you want to analyze into 
    
    %Startverzeichnis%
    
    Then klick the OK button and wait until a findings report is generated. 
    )
    FileCreateDir, %Startverzeichnis%
}
ScriptDatei := A_ScriptDir "\Findings.txt"
FileDelete, %ScriptDatei%
/*
Validate the "Work Directory" for files, guide the user and define progress bar steps.
*/
AnzahlDateien := 0
While %AnzahlDateien% = 0
{
    Loop, Files, %Startverzeichnis%*.*, F
    {
        AnzahlDateien := A_Index
    }
    If AnzahlDateien = 0
    {
        MsgBox, 262165, , 
        (LTrim
        The Working Directory is empty. Please put the MS Office files you want to analyze into the following folder and press the retry button:
        
        %Startverzeichnis%
        
        If you want to stop the MS Office file analysis, please press the cancel button.
        )
        IfMsgBox, Retry
        {
            Continue
        }
        IfMsgBox, Cancel
        {
            Goto, Ende
        }
    }
}
ProzentAdd := 100
ProzentAdd /= AnzahlDateien
/*
Start of the file Analysis.
*/
Loop, Files, %Startverzeichnis%*.*, F
{
    ResearchFileFullPath := A_LoopFileFullPath ".zip"
    AnalysePfad := A_LoopFileDir "\Analyse"
    FileDelete, %ResearchFileFullPath%
    FileRemoveDir, %AnalysePfad%, 1
    FileCreateDir, %AnalysePfad%
    FileCopy, %A_LoopFileFullPath%, %ResearchFileFullPath%
    Sleep, 300
    Unzip(ResearchFileFullPath, A_LoopFileDir "\Analyse\")
    Sleep, 300
    FileAppend, `n`n########################################`n %A_LoopFileName%`n, C:\Users\Administrator\Documents\Research Documents\60 OOXML Analyzer\Findings.txt
    If Fortschritt < 100
    {
        Fortschritt += ProzentAdd
    }
    Progress, %Fortschritt%
    Loop, Files, %AnalysePfad%\*.*, FR  ; Gehe durch Alle Dateien im oberen Verzeichnis der Analyseordners
    {
        Textify := A_LoopFileFullPath ".txt"
        FileMove, %A_LoopFileFullPath%, %Textify%
        /*
        Counters *Attack I.A.* Dependency injection / DLL hijacking through SVG image im-port in OOXML files
        */
        /*
        Counters *Attack II.C.* Hiding of malicious content in OOXML files  
        */
        IfInString, A_LoopFileName, svg
        {
            FileAppend, `n The MS Office file contains the SVG file "%A_LoopFileName%". By default`, only static svg images are allowed in OOXML files`, please be aware that the file might be altered or malicious if any property is mentioned below:`n, %ScriptDatei%
            Loop, Read, %Textify%
            {
                IfInString, A_LoopReadLine, `<`/script`>
                {
                    FileAppend, - This SVG file contains a script.`n, %ScriptDatei%
                }
                If A_LoopReadLine contains `<`/a`>`, url`(`, `<use
                {
                    FileAppend, - This SVG file contains external or internal links.`n, %ScriptDatei%
                }
                IfInString, A_LoopReadLine, video
                {
                    FileAppend, - This SVG file contains a video.`n, %ScriptDatei%
                }
            }
        }
        /*
        Counters *Attack III.B.* Unwanted SVG script and other tag execution through VBA 
        */
        IfInString, A_LoopFileName, vba
        {
            FileAppend, `nThe file contains VBA scripts with the following security relevant parameters (If nothing is mentioned below`, the MSO Analyzer did not find anything):`n, %ScriptDatei%
            Loop, Read, %Textify%
            {
                IfInString, A_LoopReadLine, `<svg
                {
                    FileAppend, - It contains a svg file.`n, %ScriptDatei%
                }
                IfInString, A_LoopReadLine, `<`/script`>
                {
                    FileAppend, - It contains an additional script tag.`n, %ScriptDatei%
                }
                If A_LoopReadLine contains `<`/a`>`, url`(`, `<use
                {
                    FileAppend, - It contains external or internal links.`n, %ScriptDatei%
                }
                IfInString, A_LoopReadLine, video
                {
                    FileAppend, - It contains a video.`n, %ScriptDatei%
                }
                IfInString, A_LoopReadLine, OLEF
                {
                    FileAppend, - The VBA script can create OLE objects.`n, %ScriptDatei%
                }
                If A_LoopReadLine contains Document_Open``, Document_Close`, Workbook_Open`, Workbook_Close`, App_Presentation`, Form_Open
                {
                    FileAppend, - The VBA script is executed automatically if VBA is allowed in the file.`n, %ScriptDatei%
                }
            }
        }
        /*
        Counters *Attack IV.D.* Information leakage through OLE2 objects in combination with VBA scripts
        */
        IfInString, A_LoopFileName, ole
        {
            FileAppend, `nThe file contains the embedded OLE object "%A_LoopFileName%".`n Inside the OLE the following is embedded;`n, %ScriptDatei%
            Loop, Read, %Textify%
            {
                IfInString, A_LoopReadLine, `<svg
                {
                    FileAppend, - It contains a svg file.`n, %ScriptDatei%
                }
                IfInString, A_LoopReadLine, `<`/script`>
                {
                    FileAppend, - It contains a script.`n, %ScriptDatei%
                }
                If A_LoopReadLine contains `<`/a`>`, url`(`, `<use
                {
                    FileAppend, - It contains external or internal links.`n, %ScriptDatei%
                }
                IfInString, A_LoopReadLine, video
                {
                    FileAppend, - It contains a video.`n, %ScriptDatei%
                }
            }
        }
        /*
        Counters *Attack II.B. & C.* Hiding of malicious SVG references inside embeddedvideos in MS Word
        */
        IfInString, A_LoopFileName, document
        {
            Gosub, VideoSuche
        }
        /*
        Counters *Attack II.B. & C.* Hiding of malicious SVG references inside embedded videos in MS PowerPoint
        */
        IfInString, A_LoopFileName, slide
        {
            Gosub, VideoSuche
        }
    }
    FileDelete, %Startverzeichnis%*.zip
}
Progress, Off
FileRead, ResultateSammler, %ScriptDatei%
Clipboard := ResultateSammler
MsgBox, 262208, Results, 
(LTrim
The Analysis has finished. The analyzed files and the findings are mentioned below. If nothing is mentioned below a file, there weren't any findings of this application. Please be aware that this does not mean it is absolutely safe to open. Always do your own due dilligence on a MS Office file.

%ResultateSammler%


The results have also been copied to the clipboard. Please feel free to forward this information to your IT Administrator if you have any further questions. 

MS Office File Analyzer, Author: Patrick Flöß, Version: 2018-12-24
)
Ende:
ExitApp
Return
/*
Scripts related to the embedded video search inside the "document.xml" for Word and inside the "slides.xml" for MS PowerPoint.
*/
VideoSuche:
Loop, Read, %Textify%
{
    IfInString, A_LoopReadLine, webVideoPr
    {
        FileAppend, `nThe document or presentation contains an embedded web video.`n, %ScriptDatei%
    }
    IfInString, A_LoopReadLine, xmlns:wp15="http://schemas.microsoft.com/office/
    {
        IfInString, A_LoopReadLine, Drawing" embeddedHtml
        {
            StringGetPos, EigentlicherLinkAnfang, A_LoopReadLine, src=&quot;, L
            EigentlicherLinkAnfang += 11
            StringGetPos, EigentlicherLinkEnde, A_LoopReadLine, &quot; frameborder, L
            EigentlicherLinkEnde -= %EigentlicherLinkAnfang%
            EigentlicherLinkEnde += 1
            StringMid, EigentlicherLink, A_LoopReadLine, EigentlicherLinkAnfang, EigentlicherLinkEnde
            FileAppend, The url is "%EigentlicherLink%". Make sure it is a web video location you can trust`, before opening the file.`n, %ScriptDatei%
        }
    }
}
Return
Return


Unzip(Sources, OutDir, SeparateFolders := false)
{
	Static vOptions := 16|256

	Sources := StrReplace(Sources, "`n", ";")
	Sources := StrReplace(Sources, ",", ";")
	Sources := Trim(Sources, ";")
	OutDir := RTrim(OutDir, "\")

	objShell := ComObjCreate("Shell.Application")
	Loop, Parse, Sources, `;, %A_Space%%A_Tab%
	{
		objSource := objShell.NameSpace(A_LoopField).Items()
		TargetDir := OutDir
		If (SeparateFolders)
		{
			SplitPath, A_LoopField,,,, FileNameNoExt
			TargetDir .= "\" FileNameNoExt
			If (!InStr(FileExist(TargetDir), "D"))
				FileCreateDir, %TargetDir%
		}
		objTarget := objShell.NameSpace(TargetDir)
		objTarget.CopyHere(objSource, vOptions)
	}
	ObjRelease(objShell)
}

Zip(FilesToZip, OutFile, SeparateFiles := false)
{
	Static vOptions := 4|16

	FilesToZip := StrReplace(FilesToZip, "`n", ";")
	FilesToZip := StrReplace(FilesToZip, ",", ";")
	FilesToZip := Trim(FilesToZip, ";")

	objShell := ComObjCreate("Shell.Application")
	If (SeparateFiles)
		SplitPath, OutFile,, OutDir
	Else
	{
		If (!FileExist(OutFile))
			CreateZipFile(OutFile)
		objTarget := objShell.Namespace(OutFile)
	}
	zipped := objTarget.items().Count
	Loop, Parse, FilesToZip, `;, %A_Space%%A_Tab%
	{
		LoopField := RTrim(A_LoopField, "\")
		Loop, Files, %LoopField%, FD
		{
			zipped++
			If (SeparateFiles)
			{
				OutFile := OutDir "\" RegExReplace(A_LoopFileName, "\.(?!.*\.).*") ".zip"
				If (!FileExist(OutFile))
					CreateZipFile(OutFile)
				objTarget := objShell.Namespace(OutFile)
				zipped := 1
			}
			For item in objTarget.Items
			{
				If (item.Name = A_LoopFileDir)
				{
					item.InvokeVerb("Delete")
					zipped--
					break
				}
				If (item.Name = A_LoopFileName)
				{
					FileRemoveDir, % A_Temp "\" item.Name, 1
					FileDelete, % A_Temp "\" item.Name
					objShell.Namespace(A_Temp).MoveHere(item)
					FileRemoveDir, % A_Temp "\" item.Name, 1
					FileDelete, % A_Temp "\" item.Name
					zipped--
					break
				}
			}
			If (A_LoopFileFullPath = OutFile)
			{
				zipped--
				continue
			}
			objTarget.CopyHere(A_LoopFileFullPath, vOptions)
			While (objTarget.items().Count != zipped)
				Sleep, 10
		}
	}
	ObjRelease(objShell)
}

CreateZipFile(sZip)
{
	CurrentEncoding := A_FileEncoding
	FileEncoding, CP1252
	Header1 := "PK" . Chr(5) . Chr(6)
	VarSetCapacity(Header2, 18, 0)
	file := FileOpen(sZip,"w")
	file.Write(Header1)
	file.RawWrite(Header2,18)
	file.close()
	FileEncoding, %CurrentEncoding%
}
