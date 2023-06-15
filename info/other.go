package info

// 去除某个元素
func removeElement(arr []string, ele string) (newArr []string) {
	for _, v := range arr {
		if v != ele {
			newArr = append(newArr, v)
		}
	}
	return newArr
}

// 字符串数组去重
func removeDuplicates(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr
}

func ReplaceElement(slice []string, old, new string) []string {
	newSlice := []string{}
	for _, v := range slice {
		if v != old {
			newSlice = append(newSlice, v)
		} else {
			newSlice = append(newSlice, new)
		}
	}
	return newSlice
}
