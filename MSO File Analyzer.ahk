﻿; MSO File Analyzer

#NoEnv
SetWorkingDir %A_ScriptDir%
CoordMode, Mouse, Window
SendMode Input
#SingleInstance Force

MSOAnalyzer:
/*
Pre-defined variables.
*/
SuchlisteDateitypen1 = .pptx,.pptm,.potx,.potm,.ppam,.ppsx,.ppsm,.sldx,.sldm,.docx,.docm,.dotx,.dotm,.docb,.xlsx,.xlsm,.xltx,.xltm,.accdt
SuchlisteDateitypen2 = .ppt,.pot,.pps,.doc,.dot,.wbk,.xlsb,.xla,.xlam,.xll,.xlw,.xls,.xlt,.xlm,.msg,.one,.accdb,.accde,.accdr,.htm,.html,.mht
SuchlisteLinks = </a>, url(, <use, <foreignobject 
SuchlisteMedia =  <video, <audio
SuchlisteVBA = Document_Open,Document_Close,Workbook_Open,Workbook_Close,App_Presentation,Form_Open
ScriptDatei := A_ScriptDir "\Findings.txt"
Startverzeichnis := A_ScriptDir "\Working Folder\"
/*
Create work directory to put MS Office files in folder and prepare the environment for the analysis. 
*/
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
FileDelete, %ScriptDatei%
FileAppend, The Analysis has finished. The analyzed files and the findings are mentioned below.`n If nothing is mentioned below a file`, there weren't any findings of this application.`n Please be aware that this does not mean it is absolutely safe to open.`n Always do your own due dilligence on a MS Office file.`n`n, %ScriptDatei%
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
Progress, b w%A_ScreenWidth% h%A_ScreenHeight%, `n`n Please wait until the files have been analyzed. The analysis takes longer if you are analyzing binary files (doc`, xls`, vba`, ...).`n You should not touch your keyboard or mouse unless the analysis is finished.`n Please do not wonder if notepad is opened and closed several times. It is part of the analysis.`n`n`nPress F8 if you want to kill the analyzer., `n`n`n`n MS Office File Analyzer ,   ; Progress bar and splash image that covers the screen area until the analysis is finished.
/*
Start of the file Analysis.
*/
Loop, Files, %Startverzeichnis%*.*, F
{
    UntersuchungsZip := A_LoopFileFullPath ".zip"
    AnalysePfad := A_LoopFileDir "\Analyse"
    FileDelete, %UntersuchungsZip%
    FileRemoveDir, %AnalysePfad%, 1
    FileCreateDir, %AnalysePfad%
    /*
    Prepare files for the analysis according to their file type. The files that can and will be analyzed are put into the analysis folder.
    */
    FileAppend, `n`n########################################`n %A_LoopFileName%`n, %ScriptDatei%
    If A_LoopFileName contains %SuchlisteDateitypen1%
    {
        FileCopy, %A_LoopFileFullPath%, %UntersuchungsZip%
        Sleep, 300
        Unzip(UntersuchungsZip, AnalysePfad)
        Sleep, 300
    }
    Else If A_LoopFileName contains %SuchlisteDateitypen2%
    {
        FileCopy, %A_LoopFileFullPath%, %AnalysePfad%
    }
    Else 
    {
        FileAppend, The file type is currently not supported and has therefore not been analyzed., %ScriptDatei%
    }
    If Fortschritt < 100
    {
        Fortschritt += ProzentAdd
    }
    Progress, %Fortschritt%
    /*
    Go through all files recursive in the "Analysis" folder.
    */
    Loop, Files, %AnalysePfad%\*.*, FR
    {
        Textify := A_LoopFileFullPath ".txt"
        FileMove, %A_LoopFileFullPath%, %Textify%
        EinzigartigeNachrichten = "" ; Variable checks if a respective finding in a file or sub-file already existed. Avoids redundant reporting and allows to report if nothing is found. 
        /*
        Counters *Attack I.A.* Dependency injection / DLL hijacking through SVG image im-port in OOXML files.
        */
        /*
        Counters *Attack II.C.* Hiding of malicious content in OOXML files.
        */
        IfInString, A_LoopFileName, svg
        {
            FileAppend, `n The MS Office file contains the SVG file "%A_LoopFileName%". By default`,`n only static svg images are allowed in OOXML files`, please be aware`n that the file might be altered or malicious if any property is mentioned below:`n, %ScriptDatei%
            Loop, Read, %Textify%
            {
                gosub, ScriptSuche
                gosub, LinkSuche
                gosub, VideoSuche1
                ; SVG specific search for binary source code inside SVG files
                If (isBinFile(A_LoopFileLongPath) ? "Binary" : "ASCII") = "Binary" 
                {
                    IfNotInString, EinzigartigeNachrichten, binary
                    {
                        FileAppend, - The SVG file contains binary source code.`n  Please inform your IT Administrator `n and do not open the file., %ScriptDatei%
                        EinzigartigeNachrichten .= "binary"
                    }
                }
            }
            gosub, NichtsGefunden
        }
        EinzigartigeNachrichten = ""
        /*
        Counters *Attack II.B. & C.* Hiding of malicious SVG references inside embedded videos in MS PowerPoint and Word.
        */
        If A_LoopFileName contains slide,document
        {
            Loop, Read, %Textify%
            {
                IfInString, A_LoopReadLine, webVideoPr
                {
                    FileAppend, `nThe presentation or document contains an embedded web video.`n, %ScriptDatei%
                }
                IfInString, A_LoopReadLine, xmlns:wp15="http://schemas.microsoft.com/office/ ; Print the web video url. 
                {
                    IfInString, A_LoopReadLine, Drawing" embeddedHtml
                    {
                        StringGetPos, EigentlicherLinkAnfang, A_LoopReadLine, src=&quot;, L
                        EigentlicherLinkAnfang += 11
                        StringGetPos, EigentlicherLinkEnde, A_LoopReadLine, &quot; frameborder, L
                        EigentlicherLinkEnde -= %EigentlicherLinkAnfang%
                        EigentlicherLinkEnde += 1
                        StringMid, EigentlicherLink, A_LoopReadLine, EigentlicherLinkAnfang, EigentlicherLinkEnde
                        FileAppend, The url is "%EigentlicherLink%".`n Make sure it is a web video location you can trust`,`n before opening the file.`n, %ScriptDatei%
                    }
                }
            }
        }
        EinzigartigeNachrichten = ""
        /*
        Counters *Attack III.B.* Unwanted SVG script and other tag execution through VBA 
        */
        If A_LoopFileName = vbaProject.bin
        {
        FileAppend, `nThe file contains VBA script with the following security relevant parameters:`n, %ScriptDatei%
        gosub, Binaerwandler
        Loop, Read, %Textify%
        {
            gosub, SvgTagSuche
            gosub, ScriptSuche
            gosub, LinkSuche
            gosub, VideoSuche1
            
            IfInString, A_LoopReadLine, OLEF
            {
                IfNotInString, EinzigartigeNachrichten, oleobj
                {
                    FileAppend, - It can create OLE objects.`n, %ScriptDatei%
                    EinzigartigeNachrichten .= "oleobj"
                }
            }
            If A_LoopReadLine contains %SuchlisteVBA%
            {
                IfNotInString, EinzigartigeNachrichten, vbaauto
                {
                    FileAppend, - It is executed automatically`n if VBA is allowed in the file.`n, %ScriptDatei%
                    EinzigartigeNachrichten .= "vbaauto"
                }
            }
        }
        If EinzigartigeNachrichten = ""
        {
            FileAppend, - Nothing found.`n, %ScriptDatei%
        }
        EinzigartigeNachrichten = ""
        }
        /*
        Counters *Attack IV.D.* Information leakage through OLE2 objects in combination with VBA scripts
        */
        IfInString, A_LoopFileName, ole
        {
            FileAppend, `nThe file contains the embedded OLE object "%A_LoopFileName%"`n with the following security relevant properties:`n, %ScriptDatei%
            Loop, Read, %Textify%
            {
                gosub, SvgTagSuche
                gosub, LinkSuche
                gosub, ScriptSuche
                gosub, VideoSuche1
            }
            gosub, NichtsGefunden
        }
        EinzigartigeNachrichten = ""
        /*
        Analysis of Outlook, OneNote, HTML, MHT and binary files.
        */
        If A_LoopFileName contains %SuchlisteDateitypen2%
        {
            gosub, Binaerwandler
            Loop, Read, %Textify%
            {
                gosub, SvgTagSuche
                gosub, ScriptSuche
                gosub, LinkSuche
                gosub, VideoSuche1
            } 
            gosub, NichtsGefunden
        }
    }
    EinzigartigeNachrichten = ""
    FileDelete, %Startverzeichnis%*.zip  ; File loop end.
}
Progress, Off
FileAppend, `n`n`nThe results have also been copied to the clipboard.`n Please feel free to forward this information to your`n IT Administrator if you have any further questions. `n`nMS Office File Analyzer`, Author: Patrick Flöß`, Version: 2018-12-24, %ScriptDatei%
If !IsObject(ie)
	ie := ComObjCreate("InternetExplorer.Application")
ie.Visible := true
ie.Navigate(ScriptDatei)
FileRead, ResultateSammler, %ScriptDatei%
Clipboard := ResultateSammler
Ende:
ExitApp
Return

/*
Subs to avoid redundant code and reduce the carbon footprint of the application. 
*/

Binaerwandler: ; Change binary files to normal text files.
Clipboard =  
Run, Notepad "%Textify%" 
WinActivate, ahk_class Notepad
WinWaitActive, ahk_class Notepad
Sleep 1000
Send, {Control Down}{a}{Control Up}
Sleep, 300 
Send, {Control Down}{c}{Control Up}
ClipWait 
Send, {Control Down}{v}{Control Up}
Sleep, 300 
Send, {Control Down}{s}{Control Up}
Sleep, 300 
WinClose, ahk_class Notepad 
Sleep, 300 
IfWinExist, ahk_class #32770 
{ 
    Send, {Enter} 
}
WinWaitClose, ahk_class Notepad
Clipboard = 
return

ScriptSuche: ; Search for script tags.
IfInString, A_LoopReadLine, `<`/script`>
{
    IfNotInString, EinzigartigeNachrichten, script
    {
        FileAppend, - It contains a script.`n, %ScriptDatei%
        EinzigartigeNachrichten .= "script"
    }
}
return
 
LinkSuche: ; Search for anything that could function as a link in SVG files.
If A_LoopReadLine contains %SuchlisteLinks%
{
    IfNotInString, EinzigartigeNachrichten, links
    {
        FileAppend, - It contains external or internal links or references.`n, %ScriptDatei%
        EinzigartigeNachrichten .= "links"
    }
}
return

VideoSuche1: ; Search for tags related to videos.
IfInString, A_LoopReadLine, %SuchlisteMedia%
{
    IfNotInString, EinzigartigeNachrichten, media
    {
        FileAppend, - It contains video or audio.`n, %ScriptDatei%
        EinzigartigeNachrichten .= "media"
    }
}
return

SvgTagSuche: ; Search if there is any SVG starting tag.
IfInString, A_LoopReadLine, `<svg
{
IfNotInString, EinzigartigeNachrichten, svg
    {
        FileAppend, - It contains a svg file.`n, %ScriptDatei%
        EinzigartigeNachrichten .= "svg"
    }
}
return

NichtsGefunden:
If EinzigartigeNachrichten = ""
            {
                FileAppend,  - Nothing found.`n, %ScriptDatei%
            }
return
/*
Binary Scanner Function 
Source: https://www.autohotkey.com/boards/viewtopic.php?f=76&t=144&start=20
*/
isBinFile(Filename,NumBytes=32,Minimum=4,complexunicode=1) {
	
	file:=FileOpen(Filename,"r")
	file.Position:=0 ;force position to 0 (zero)
	nbytes:=file.RawRead(rawbytes,NumBytes) ;read bytes
	file.Close() ;close file
	
	if (nbytes < Minimum) ;recommended 4 minimum for unicode detection
		return 0 ;asume text file, if too short
	
	t:=0, i:=0, bytes:=[] ;Initialize vars
	
	loop % nbytes ;create c-style bytes array
		bytes[(A_Index-1)]:=Numget(&rawbytes,(A_Index-1),"UChar")
	
	;determine BOM if possible/existant
	if (bytes[0]=0xFE && bytes[1]=0xFF)
		|| (bytes[0]=0xFF && bytes[1]=0xFE)
		return 0 ;text Utf-16 BE/LE file
	if (bytes[0]=0xEF && bytes[1]=0xBB && bytes[2]=0xBF)
		return 0 ;text Utf-8 file
	if (bytes[0]=0x00 && bytes[1]=0x00
		&& bytes[2]=0xFE && bytes[3]=0xFF)
		|| (bytes[0]=0xFF && bytes[1]=0xFE
		&& bytes[2]=0x00 && bytes[3]=0x00)
		return 0 ;text Utf-32 BE/LE file
		
	while(i<nbytes) {	
		;// ASCII
		if( bytes[i] == 0x09 || bytes[i] == 0x0A || bytes[i] == 0x0D
			|| (0x20 <= bytes[i] && bytes[i] <= 0x7E) ) {
			i += 1
			continue
		}
		;// non-overlong 2-byte
		if( (0xC2 <= bytes[i] && bytes[i] <= 0xDF)
			&& (0x80 <= bytes[i+1] && bytes[i+1] <= 0xBF) ) {
			i += 2
			continue
		}
		;// excluding overlongs, straight 3-byte, excluding surrogates
		if( ( bytes[i] == 0xE0 && (0xA0 <= bytes[i+1] && bytes[i+1] <= 0xBF)
			&& (0x80 <= bytes[i+2] && bytes[i+2] <= 0xBF) )
			|| ( ((0xE1 <= bytes[i] && bytes[i] <= 0xEC)
			|| bytes[i] == 0xEE || bytes[i] == 0xEF)
			&& (0x80 <= bytes[i+1] && bytes[i+1] <= 0xBF)
			&& (0x80 <= bytes[i+2] && bytes[i+2] <= 0xBF) 	)
			|| ( bytes[i] == 0xED && (0x80 <= bytes[i+1] && bytes[i+1] <= 0x9F)
			&& (0x80 <= bytes[i+2] && bytes[i+2] <= 0xBF) ) ) {
			i += 3
			continue
		}
		;// planes 1-3, planes 4-15, plane 16
		if( ( bytes[i] == 0xF0 && (0x90 <= bytes[i+1] && bytes[i+1] <= 0xBF)
			&& (0x80 <= bytes[i+2] && bytes[i+2] <= 0xBF)
			&& (0x80 <= bytes[i+3] && bytes[i+3] <= 0xBF) )
			|| ( (0xF1 <= bytes[i] && bytes[i] <= 0xF3)
			&& (0x80 <= bytes[i+1] && bytes[i+1] <= 0xBF)
			&& (0x80 <= bytes[i+2] && bytes[i+2] <= 0xBF)
			&& (0x80 <= bytes[i+3] && bytes[i+3] <= 0xBF) )
			|| ( bytes[i] == 0xF4 && (0x80 <= bytes[i+1] && bytes[i+1] <= 0x8F)
			&& (0x80 <= bytes[i+2] && bytes[i+2] <= 0xBF)
			&& (0x80 <= bytes[i+3] && bytes[i+3] <= 0xBF) ) ) {
			i += 4
			continue
		}
		t:=1
		break
	}
	
	if (t=0) ;the while-loop has no fails, then confirmed utf-8
		return 0
	;else do nothing and check again with the classic method below
	
	loop, %nbytes% {
		if (bytes[(A_Index-1)]<9) or (bytes[(A_Index-1)]>126)
			or ((bytes[(A_Index-1)]<32) and (bytes[(A_Index-1)]>13))
			return 1
	}
	
	return 0
}
/* 
Zip and unzip related functions.
*/
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

/*
Additional Controls.
*/
F8::ExitApp
