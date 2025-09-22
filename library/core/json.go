/*
MIT License

Copyright 2022 Mitch Allen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package libcore

// github.com/trapcodeio/go-strip-json-comments

const (
	notInsideComment = 0
	singleComment    = 1
	multiComment     = 2
)

func isEscaped(jsonString string, quotePosition int) bool {
	index := quotePosition - 1
	backslashCount := 0

	if index < 0 {
		return false
	}

	for string(jsonString[index]) == "\\" {
		index -= 1
		backslashCount += 1
	}

	return backslashCount%2 == 1
}

// strip comments and trailing commas  from JSON string
func StripJSON(jsonString string) string {
	isInsideString := false
	isInsideComment := notInsideComment
	offset := 0
	buffer := ""
	result := ""
	commaIndex := -1

	for index := 0; index < len(jsonString); index++ {
		currentCharacter := string(jsonString[index])
		nextCharacter := ""

		if index+1 < len(jsonString) {
			nextCharacter = string(jsonString[index+1])
		}

		if isInsideComment == notInsideComment && currentCharacter == `"` {
			// Enter or exit string
			escaped := isEscaped(jsonString, index)
			if !escaped {
				isInsideString = !isInsideString
			}
		}

		if isInsideString {
			continue
		}

		if isInsideComment == notInsideComment && currentCharacter+nextCharacter == "//" {
			// Enter single-line comment
			buffer += jsonString[offset:index]
			offset = index
			isInsideComment = singleComment
			index++
		} else if isInsideComment == singleComment && currentCharacter+nextCharacter == "\r\n" {
			// Exit single-line comment via \r\n
			index++
			isInsideComment = notInsideComment
			offset = index
		} else if isInsideComment == singleComment && currentCharacter == "\n" {
			// Exit single-line comment via \n
			isInsideComment = notInsideComment
			offset = index
		} else if isInsideComment == notInsideComment && currentCharacter+nextCharacter == "/*" {
			// Enter multiline comment
			buffer += jsonString[offset:index]
			offset = index
			isInsideComment = multiComment
			index++

		} else if isInsideComment == multiComment && currentCharacter+nextCharacter == "*/" {
			// Exit multiline comment
			index++
			isInsideComment = notInsideComment
			offset = index + 1

		} else if isInsideComment == notInsideComment {
			if commaIndex != -1 {
				if currentCharacter == "}" || currentCharacter == "]" {
					// Strip trailing comma
					buffer += jsonString[offset:index]
					result += buffer[1:]
					buffer = ""
					offset = index
					commaIndex = -1
				} else if currentCharacter != " " && currentCharacter != "\t" && currentCharacter != "\r" && currentCharacter != "\n" {
					// Hit non-whitespace following a comma; comma is not trailing
					buffer += jsonString[offset:index]
					offset = index
					commaIndex = -1
				}
			} else if currentCharacter == "," {
				// Flush buffer prior to this point, and save new comma index
				result += buffer + jsonString[offset:index]
				buffer = ""
				offset = index
				commaIndex = index

			}
		}
	}

	var end string
	if isInsideComment > notInsideComment {
		end = ""
	} else {
		end = jsonString[offset:]
	}

	return result + buffer + end
}
