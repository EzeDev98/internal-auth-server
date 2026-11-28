package com.internal.auth.common.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Lightweight endpoint used to keep the service awake. */
@RestController
@RequestMapping("${app.title}")
public class KeepAliveController {

    @GetMapping("/keep-alive")
    public ResponseEntity<String> keepAlive() {
        return ResponseEntity.ok("OK");
    }
}
