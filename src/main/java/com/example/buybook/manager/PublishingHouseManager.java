package com.example.buybook.manager;

import com.example.buybook.dto.PublishingHouseDto;
import com.example.buybook.dto.PublishingHouseDtoManager;
import com.example.buybook.entity.PublishingHouse;
import com.example.buybook.exception.PublishingHouseNotFoundException;
import com.example.buybook.mapper.PublishingHouseMapper;
import com.example.buybook.repository.PublishingHouseRepository;
import com.example.buybook.service.PublishingHouseService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;
//@Component
@Service
@AllArgsConstructor
public class PublishingHouseManager implements PublishingHouseService{

    private final PublishingHouseRepository publishingHouseRepository;

    private final PublishingHouseDtoManager publishingHouseDtoManager;

    private final PublishingHouseMapper publishingHouseMapper;
    @Override
    public List<PublishingHouseDto> getAll() {

        return publishingHouseRepository.findAll().stream().
                map(publishingHouseMapper::topublishingHouseDto).toList();
    }

    @Override
    public PublishingHouseDto getById(int id) {

        return publishingHouseRepository.findById(id).stream().
                map(publishingHouseMapper::topublishingHouseDto).
                findFirst().orElseThrow(()-> new PublishingHouseNotFoundException("PublishingHouse tapilmadi"));
    }

    @Override
    public void addPublishingHouse(PublishingHouseDto publishingHouseDto) {
        publishingHouseRepository.save(publishingHouseMapper.toPublishingHouseEntity(publishingHouseDto));

    }

    @Override
    public void deletePublishingHouse(int id) {
        publishingHouseRepository.deleteById(id);

    }
}
