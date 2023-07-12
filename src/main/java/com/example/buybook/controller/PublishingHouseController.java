package com.example.buybook.controller;

import com.example.buybook.dto.PublishingHouseDto;
import com.example.buybook.entity.PublishingHouse;
import com.example.buybook.manager.PublishingHouseManager;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/publishinghouses")
public class PublishingHouseController {

    private final PublishingHouseManager publishingHouseManager;

    public PublishingHouseController(PublishingHouseManager publishingHouseManager) {
        this.publishingHouseManager = publishingHouseManager;
    }
    @GetMapping
    public List<PublishingHouseDto> getAll(){
        return publishingHouseManager.getAll();
    }
    @GetMapping("/{id}")
    public PublishingHouseDto getById(@PathVariable int id){
        return publishingHouseManager.getById(id);
    }
    @PostMapping
    @ResponseStatus(code= HttpStatus.CREATED)
    public void addPublishingHouse(@RequestBody PublishingHouseDto publishingHouseDto){
        publishingHouseManager.addPublishingHouse(publishingHouseDto);
    }
    @DeleteMapping("/{id}")
    public void deletePublishingHouses(@PathVariable int id){
        publishingHouseManager.deletePublishingHouse(id);
    }

}
