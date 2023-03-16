package io.security.corespringsecurity2.controller;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {
	

	@GetMapping(value="/")
	public String home() throws Exception {
		return "home";
	}

	@GetMapping(value="/mypage")
	public String mypage() throws Exception {
		return "mypage";
	}


	@GetMapping(value="/config")
	public String config() throws Exception {
		return "config";
	}
}
