package card

import (
	"crypto/hmac"
	"crypto/sha256"
)

const (
	minPINLength = 4
	maxPINLength = 8
)

// validatePIN enforces digits only, 4-8 long, and rejects the PINs people
// pick first. With only DefaultMaxAttempts guesses, the attacker who has a
// card tries exactly these, so a real PIN distribution (not a random one)
// decides how safe a stolen card is: 1234/1111/0000 alone cover ~20% of
// real-world 4-digit PINs, and repeats, keypad lines and years most of the
// rest of the top list.
func validatePIN(pin string) error {
	if len(pin) < minPINLength || len(pin) > maxPINLength {
		return ErrWeakPIN
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return ErrWeakPIN
		}
	}
	if isRun(pin) || isRepeatedUnit(pin) || isPairs(pin) || isPalindrome(pin) || isYear(pin) || commonPINs[pin] {
		return ErrWeakPIN
	}
	return nil
}

// isRun: every digit one more (1234) or one less (9876) than the previous.
func isRun(pin string) bool {
	up, down := true, true
	for i := 1; i < len(pin); i++ {
		d := int(pin[i]) - int(pin[i-1])
		up = up && d == 1
		down = down && d == -1
	}
	return up || down
}

// isRepeatedUnit: a short unit repeated (1111, 1212, 123123, 696969).
func isRepeatedUnit(pin string) bool {
	for unit := 1; unit <= len(pin)/2; unit++ {
		if len(pin)%unit != 0 {
			continue
		}
		repeated := true
		for i := unit; i < len(pin); i++ {
			if pin[i] != pin[i-unit] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}

// isPairs: digits doubled in pairs (1122, 112233, 11223344).
func isPairs(pin string) bool {
	if len(pin)%2 != 0 {
		return false
	}
	for i := 0; i < len(pin); i += 2 {
		if pin[i] != pin[i+1] {
			return false
		}
	}
	return true
}

// isPalindrome: reads the same backwards (1221, 123321).
func isPalindrome(pin string) bool {
	for i, j := 0, len(pin)-1; i < j; i, j = i+1, j-1 {
		if pin[i] != pin[j] {
			return false
		}
	}
	return true
}

// isYear: 4-digit years 1900-2099, the usual birth or memorable years.
func isYear(pin string) bool {
	return len(pin) == 4 && (pin[:2] == "19" || pin[:2] == "20")
}

// commonPINs are frequent choices the patterns above do not cover: keypad
// lines and shapes, and words spelled on a phone keypad.
var commonPINs = map[string]bool{
	// keypad columns, rows and diagonals
	"2580": true, "0852": true, "1470": true, "0741": true, "3690": true, "0963": true,
	"1475": true, "7410": true, "0147": true, "3698": true, "9630": true, "0258": true, "8520": true,
	"1379": true, "9731": true, "1397": true, "7913": true, "3179": true, "1793": true,
	"1590": true, "7530": true, "3570": true, "1595": true, "7537": true, "1357": true, "2468": true,
	"147258": true, "258369": true, "147258369": true, "159753": true, "357159": true, "789456": true,
	"456123": true, "741852": true, "852963": true, "963852": true, "369258": true,
	// keypad words and other well-known picks
	"5683": true, "1004": true, "1314": true, "5201314": true, "520520": true, "0007": true,
	"1235": true, "1236": true, "1478": true, "3214": true, "1243": true, "4231": true,
	"0101": true, "1010": true, "1001": true, "0110": true, "9999": true, "0911": true, "1911": true,
}

// hashPIN binds the PIN to one card id and a server-side pepper. A PIN has so
// little entropy that any hash of it alone is reversible in milliseconds; the
// pepper (kept outside the database) is what makes a leaked table useless.
func hashPIN(pepper []byte, cardID, pin string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(cardID))
	mac.Write([]byte{0})
	mac.Write([]byte(pin))
	return mac.Sum(nil)
}
