package com.example.resourceserver.web;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;
@RestController
public class ApiController {
  @GetMapping("/public/health") public Map<String,Object> health(){ return Map.of("status","ok"); }
  @GetMapping("/data") public Map<String,Object> data(){ return Map.of("message","protected data","value",42); }
}
