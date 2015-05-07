package validation

import (
  "strings"
  )


func Method(method string) bool {
  switch strings.ToUpper(method){
    case "GET":
      return true
    case "PUT", "POST":
      return true
    default:
      return false
  }
  return true
}
